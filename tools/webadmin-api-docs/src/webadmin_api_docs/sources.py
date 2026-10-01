"""Optional local source-data configuration and selective asset setup."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Final

import click
import httpx2

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.logging import info
from webadmin_api_docs.logging import task
from webadmin_api_docs.logging import warn

CONFIG_NAME: Final = ".webadmin-api-docs.local.toml"
SOURCE_DATA_DIRECTORY: Final = ".source-data"
WEB_ASSETS_DIRECTORY: Final = "rs2-server-web"
DEPOTDOWNLOADER_VERSION: Final = "3.4.0"
SERVER_APP_ID: Final = 418480
SERVER_DEPOT_ID: Final = 418481
FILE_LIST_CONTENT: Final = "regex:(^|.*/)(ServerAdmin|images)/.*\n"


class SourceConfigurationError(ValueError):
    """A configured source path is absent or has an unexpected layout."""


@dataclass(frozen=True, slots=True)
class DepotDownloaderPin:
    """A reviewed upstream archive and its expected executable."""

    platform_key: str
    archive_name: str
    archive_sha256: str
    executable_name: str
    executable_sha256: str

    @property
    def url(self) -> str:
        """Return the pinned release-asset location."""
        return (
            "https://github.com/SteamRE/DepotDownloader/releases/download/"
            f"DepotDownloader_{DEPOTDOWNLOADER_VERSION}/{self.archive_name}"
        )


DEPOTDOWNLOADER_PINS: Final = {
    "linux-x64": DepotDownloaderPin(
        "linux-x64",
        "DepotDownloader-linux-x64.zip",
        "a999dec66b4850fc961bd50366696d23c2d0fad7b18790e6a5647b2f19097a53",
        "DepotDownloader",
        "d62a1721564bdb96bacd9285bb5f96180a45202e82a9f85c6a88e5e8ee5f992c",
    ),
    "windows-x64": DepotDownloaderPin(
        "windows-x64",
        "DepotDownloader-windows-x64.zip",
        "41c9e9f0df54b3ad02e67a11726756e5c73283bd7c2e1b04acfa5ae4c2ed3767",
        "DepotDownloader.exe",
        "6281279efce8f1e20db9532a58e42382f81afb9e3827a8b965ffcb43fbe4531f",
    ),
}


@dataclass(frozen=True, slots=True)
class LocalSourceConfig:
    """Optional externally managed directories remembered for this checkout."""

    sdk_scripts_dir: Path | None = None
    web_assets_dir: Path | None = None


@dataclass(frozen=True, slots=True)
class SetupPlan:
    """The source selections and idempotent work selected by setup."""

    sdk_scripts_dir: Path
    web_assets_dir: Path
    web_assets_external: bool
    fetch_web_assets: bool


def project_root() -> Path:
    """Resolve the project root without assuming a checkout location."""
    return Path(__file__).resolve().parents[2]


def config_path(root: Path) -> Path:
    """Return the ignored local configuration path."""
    return root / CONFIG_NAME


def managed_web_assets_dir(root: Path) -> Path:
    """Return the default project-managed web-assets cache directory."""
    return root / SOURCE_DATA_DIRECTORY / WEB_ASSETS_DIRECTORY


def load_local_config(root: Path) -> LocalSourceConfig:
    """Load local external paths without silently accepting malformed TOML."""
    path = config_path(root)
    if not path.is_file():
        return LocalSourceConfig()
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SourceConfigurationError(f"Unable to read {path.name}: {error}") from error
    sources = payload.get("sources", {})
    if not isinstance(sources, dict):
        raise SourceConfigurationError("[sources] must be a TOML table")

    def configured_path(key: str) -> Path | None:
        value = sources.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise SourceConfigurationError(f"sources.{key} must be a non-empty path string")
        return Path(value).expanduser().resolve()

    return LocalSourceConfig(
        sdk_scripts_dir=configured_path("sdk_scripts_dir"),
        web_assets_dir=configured_path("web_assets_dir"),
    )


def write_local_config(root: Path, config: LocalSourceConfig) -> None:
    """Persist selected external paths in a small ignored TOML file."""
    lines = ["[sources]"]
    if config.sdk_scripts_dir is not None:
        lines.append(f"sdk_scripts_dir = {json.dumps(str(config.sdk_scripts_dir))}")
    if config.web_assets_dir is not None:
        lines.append(f"web_assets_dir = {json.dumps(str(config.web_assets_dir))}")
    config_path(root).write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_sdk_scripts_dir(path: Path) -> Path:
    """Validate the manually supplied licensed SDK script-source root."""
    resolved = path.expanduser().resolve()
    required = (resolved / "WebAdmin" / "Classes", resolved / "ROGame" / "Classes")
    if not resolved.is_dir() or any(not item.is_dir() for item in required):
        raise SourceConfigurationError("SDK path must contain WebAdmin/Classes and ROGame/Classes")
    return resolved


def validate_web_assets_dir(path: Path) -> Path:
    """Validate a normalized root containing the bundled WebAdmin assets."""
    resolved = path.expanduser().resolve()
    required = (resolved / "ServerAdmin" / "login.html", resolved / "images" / "ro2.css")
    if not resolved.is_dir() or any(not item.is_file() for item in required):
        raise SourceConfigurationError(
            "Web-assets path must contain ServerAdmin/login.html and images/ro2.css"
        )
    return resolved


def make_setup_plan(
    root: Path,
    config: LocalSourceConfig,
    *,
    sdk_scripts_dir: Path | None,
    web_assets_dir: Path | None,
    force: bool,
) -> SetupPlan:
    """Choose setup work without performing downloads or filesystem mutations."""
    configured_sdk = sdk_scripts_dir or config.sdk_scripts_dir
    if configured_sdk is None:
        raise SourceConfigurationError(
            "SDK source is required; pass --sdk-sources-dir PATH or configure it first"
        )
    selected_sdk = validate_sdk_scripts_dir(configured_sdk)
    configured_web = web_assets_dir or config.web_assets_dir
    if configured_web is not None:
        return SetupPlan(
            selected_sdk,
            validate_web_assets_dir(configured_web),
            web_assets_external=True,
            fetch_web_assets=False,
        )
    selected_web = managed_web_assets_dir(root)
    try:
        validate_web_assets_dir(selected_web)
    except SourceConfigurationError:
        fetch_web_assets = True
    else:
        fetch_web_assets = force
    return SetupPlan(selected_sdk, selected_web, False, fetch_web_assets)


def sha256_file(path: Path) -> str:
    """Return a lower-case SHA-256 digest without loading the file at once."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def selected_platform_pin() -> DepotDownloaderPin:
    """Select a supported pin for the current OS and CPU architecture."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"}:
        raise SourceConfigurationError(f"Unsupported DepotDownloader architecture: {machine}")
    try:
        return DEPOTDOWNLOADER_PINS[f"{system}-x64"]
    except KeyError as error:
        raise SourceConfigurationError(f"Unsupported DepotDownloader platform: {system}") from error


def validate_zip_members(bundle: zipfile.ZipFile, pin: DepotDownloaderPin) -> None:
    """Reject archive paths other than the reviewed self-contained executable."""
    names = bundle.namelist()
    expected = [pin.executable_name]
    if names != expected:
        raise SourceConfigurationError(
            "Downloader archive has unexpected contents:"
            f" expected: {names}"
            f", actual: {expected}"
        )
    for name in names:
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts or "\\" in name:
            raise SourceConfigurationError("Downloader archive contains an unsafe path")


def _download(url: str, destination: Path) -> None:
    with (
        httpx2.Client(follow_redirects=True, timeout=60.0) as client,
        client.stream("GET", url) as response,
        destination.open("wb") as stream,
    ):
        response.raise_for_status()
        for chunk in response.iter_bytes():
            stream.write(chunk)


def _validate_downloader(executable: Path, pin: DepotDownloaderPin) -> None:
    if sha256_file(executable) != pin.executable_sha256:
        raise SourceConfigurationError("DepotDownloader executable hash does not match its pin")
    result = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if DEPOTDOWNLOADER_VERSION not in result.stdout + result.stderr:
        raise SourceConfigurationError("DepotDownloader executable reports an unexpected version")


def bootstrap_downloader(root: Path, *, force: bool) -> Path:
    """Fetch, verify, and cache the reviewed DepotDownloader binary."""
    pin = selected_platform_pin()
    destination = root / SOURCE_DATA_DIRECTORY / "tools" / "depotdownloader" / DEPOTDOWNLOADER_VERSION
    executable = destination / pin.executable_name
    if executable.is_file() and not force:
        try:
            _validate_downloader(executable, pin)
        except (OSError, SourceConfigurationError, subprocess.SubprocessError) as error:
            warn(f"Cached DepotDownloader is invalid and will be replaced: {error}")
        else:
            info(f"Reusing verified DepotDownloader from {executable}")
            return executable
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="depotdownloader-", dir=destination.parent) as raw:
        staging = Path(raw)
        archive = staging / pin.archive_name
        staged_tool = staging / "tool"
        staged_tool.mkdir()
        task(f"Downloading pinned DepotDownloader {DEPOTDOWNLOADER_VERSION}")
        _download(pin.url, archive)
        if sha256_file(archive) != pin.archive_sha256:
            raise SourceConfigurationError("DepotDownloader archive hash does not match its pin")
        with zipfile.ZipFile(archive) as bundle:
            validate_zip_members(bundle, pin)
            bundle.extract(pin.executable_name, staged_tool)
        staged_executable = staged_tool / pin.executable_name
        if os.name != "nt":
            staged_executable.chmod(0o755)
        _validate_downloader(staged_executable, pin)
        _replace_directory(staged_tool, destination)
    info(f"Cached verified DepotDownloader at {executable}")
    return executable


def _run_downloader(
    executable: Path,
    output_dir: Path,
    file_list: Path,
    *,
    app_id: int,
    depot_id: int,
) -> None:
    subprocess.run(
        [
            str(executable), "-app", str(app_id), "-depot", str(depot_id), "-os", "windows",
            "-dir", str(output_dir), "-filelist", str(file_list),
        ],
        check=True,
        timeout=900,
    )


def _find_downloaded_assets(download_dir: Path) -> tuple[Path, Path]:
    matches = [
        (server_admin, server_admin.parent / "images")
        for server_admin in download_dir.rglob("ServerAdmin")
        if server_admin.is_dir() and (server_admin.parent / "images").is_dir()
    ]
    valid = [pair for pair in matches if (pair[0] / "login.html").is_file() and (pair[1] / "ro2.css").is_file()]
    if len(valid) != 1:
        raise SourceConfigurationError("Selective depot download did not contain one valid asset pair")
    return valid[0]


def _replace_directory(staged: Path, destination: Path) -> None:
    backup = destination.with_name(f"{destination.name}.previous")
    if backup.exists():
        shutil.rmtree(backup)
    if destination.exists():
        destination.replace(backup)
    try:
        staged.replace(destination)
    except OSError:
        if backup.exists():
            backup.replace(destination)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def fetch_web_assets(root: Path, *, downloader: Path, app_id: int, depot_id: int) -> Path:
    """Selectively download and atomically install normalized WebAdmin assets."""
    cache_root = root / SOURCE_DATA_DIRECTORY
    cache_root.mkdir(parents=True, exist_ok=True)
    destination = managed_web_assets_dir(root)
    with tempfile.TemporaryDirectory(prefix="rs2-web-assets-", dir=cache_root) as raw:
        staging = Path(raw)
        file_list = staging / "filelist.txt"
        file_list.write_text(FILE_LIST_CONTENT, encoding="utf-8")
        task("Downloading bundled WebAdmin templates and static assets")
        _run_downloader(downloader, staging / "depot", file_list, app_id=app_id, depot_id=depot_id)
        server_admin, images = _find_downloaded_assets(staging / "depot")
        normalized = staging / WEB_ASSETS_DIRECTORY
        normalized.mkdir()
        shutil.copytree(server_admin, normalized / "ServerAdmin")
        shutil.copytree(images, normalized / "images")
        validate_web_assets_dir(normalized)
        _replace_directory(normalized, destination)
    return destination


def _updated_config(
    config: LocalSourceConfig, *, sdk_scripts_dir: Path | None, web_assets_dir: Path | None
) -> LocalSourceConfig:
    return LocalSourceConfig(
        validate_sdk_scripts_dir(sdk_scripts_dir) if sdk_scripts_dir is not None else config.sdk_scripts_dir,
        validate_web_assets_dir(web_assets_dir) if web_assets_dir is not None else config.web_assets_dir,
    )


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def sources() -> None:
    """Configure optional local RS2 source data."""


@sources.command("status")
def status() -> None:
    """Report configured sources without changing state."""
    root = project_root()
    try:
        config = load_local_config(root)
        if config.sdk_scripts_dir is None:
            warn("SDK source is not configured")
        else:
            info(f"SDK source: {validate_sdk_scripts_dir(config.sdk_scripts_dir)}")
        if config.web_assets_dir is not None:
            info(f"External web-assets source: {validate_web_assets_dir(config.web_assets_dir)}")
        else:
            assets = managed_web_assets_dir(root)
            try:
                validate_web_assets_dir(assets)
            except SourceConfigurationError:
                warn(f"Managed web-assets cache is not available: {assets}")
            else:
                info(f"Managed web-assets cache: {assets}")
    except SourceConfigurationError as error:
        warn(str(error))
        raise click.exceptions.Exit(1) from error


@sources.command("configure")
@click.option("--sdk-sources-dir", type=click.Path(path_type=Path))
@click.option("--web-assets-dir", type=click.Path(path_type=Path))
def configure(sdk_sources_dir: Path | None, web_assets_dir: Path | None) -> None:
    """Validate and remember user-supplied external source directories."""
    if sdk_sources_dir is None and web_assets_dir is None:
        raise click.UsageError("Supply --sdk-sources-dir and/or --web-assets-dir")
    root = project_root()
    try:
        config = _updated_config(load_local_config(root), sdk_scripts_dir=sdk_sources_dir, web_assets_dir=web_assets_dir)
        write_local_config(root, config)
    except SourceConfigurationError as error:
        warn(str(error))
        raise click.exceptions.Exit(1) from error
    info(f"Saved local source configuration to {config_path(root)}")


@sources.command("setup")
@click.option("--sdk-sources-dir", type=click.Path(path_type=Path))
@click.option("--web-assets-dir", type=click.Path(path_type=Path))
@click.option("--force", is_flag=True, help="Refresh project-managed downloads")
@click.option("--depot-downloader", type=click.Path(path_type=Path))
@click.option("--allow-unverified-downloader", is_flag=True)
@click.option("--app-id", default=SERVER_APP_ID, show_default=True, type=int)
@click.option("--depot-id", default=SERVER_DEPOT_ID, show_default=True, type=int)
def setup(
    sdk_sources_dir: Path | None,
    web_assets_dir: Path | None,
    force: bool,
    depot_downloader: Path | None,
    allow_unverified_downloader: bool,
    app_id: int,
    depot_id: int,
) -> None:
    """Set up validated sources, downloading only missing managed assets."""
    root = project_root()
    try:
        config = load_local_config(root)
        plan = make_setup_plan(root, config, sdk_scripts_dir=sdk_sources_dir, web_assets_dir=web_assets_dir, force=force)
        info(f"Using SDK source: {plan.sdk_scripts_dir}")
        if plan.web_assets_external:
            info(f"Using external web-assets source: '{plan.web_assets_dir}'")
        elif plan.fetch_web_assets:
            info(f"Refreshing managed web-assets cache: '{plan.web_assets_dir}'")
            if depot_downloader is not None:
                if not allow_unverified_downloader:
                    raise SourceConfigurationError("--depot-downloader requires --allow-unverified-downloader")
                downloader = depot_downloader.expanduser().resolve()
                if not downloader.is_file():
                    raise SourceConfigurationError("Supplied DepotDownloader path is not a file")
                warn(f"Using unverified operator-supplied DepotDownloader: {downloader}")
            else:
                downloader = bootstrap_downloader(root, force=force)
            fetch_web_assets(root, downloader=downloader, app_id=app_id, depot_id=depot_id)
            info(f"Installed managed web assets at {plan.web_assets_dir}")
        else:
            info(f"Reusing managed web-assets cache: {plan.web_assets_dir}")
        updated = _updated_config(config, sdk_scripts_dir=sdk_sources_dir, web_assets_dir=web_assets_dir)
        if updated != config:
            write_local_config(root, updated)
            info(f"Saved local source configuration to {config_path(root)}")
    except (OSError, SourceConfigurationError, httpx2.RequestError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        warn(str(error))
        raise click.exceptions.Exit(1) from error
