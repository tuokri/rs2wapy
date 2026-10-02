# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Focused unit tests for source setup decisions and verification helpers."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from webadmin_api_docs.sources import DEPOTDOWNLOADER_PINS
from webadmin_api_docs.sources import LocalSourceConfig
from webadmin_api_docs.sources import SourceConfigurationError
from webadmin_api_docs.sources import make_setup_plan
from webadmin_api_docs.sources import sha256_file
from webadmin_api_docs.sources import validate_zip_members


def create_sdk(root: Path) -> Path:
    (root / "WebAdmin" / "Classes").mkdir(parents=True)
    (root / "ROGame" / "Classes").mkdir(parents=True)
    return root


def create_web_assets(root: Path) -> Path:
    (root / "ServerAdmin").mkdir(parents=True)
    (root / "images").mkdir()
    (root / "ServerAdmin" / "login.html").touch()
    (root / "images" / "ro2.css").touch()
    return root


def test_setup_requires_sdk_before_selecting_download(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigurationError, match="SDK source is required"):
        make_setup_plan(
            tmp_path,
            LocalSourceConfig(),
            sdk_scripts_dir=None,
            web_assets_dir=None,
            force=False,
        )


def test_setup_reuses_valid_managed_cache(tmp_path: Path) -> None:
    sdk = create_sdk(tmp_path / "sdk")
    create_web_assets(tmp_path / ".source-data" / "rs2-server-web")

    plan = make_setup_plan(
        tmp_path,
        LocalSourceConfig(sdk_scripts_dir=sdk),
        sdk_scripts_dir=None,
        web_assets_dir=None,
        force=False,
    )

    assert not plan.fetch_web_assets
    assert not plan.web_assets_external
    assert plan.sdk_scripts_dir == sdk


def test_force_refreshes_only_managed_assets(tmp_path: Path) -> None:
    sdk = create_sdk(tmp_path / "sdk")
    create_web_assets(tmp_path / ".source-data" / "rs2-server-web")

    plan = make_setup_plan(
        tmp_path,
        LocalSourceConfig(sdk_scripts_dir=sdk),
        sdk_scripts_dir=None,
        web_assets_dir=None,
        force=True,
    )

    assert plan.fetch_web_assets
    assert plan.sdk_scripts_dir == sdk


def test_explicit_sdk_and_external_assets_override_config(tmp_path: Path) -> None:
    configured_sdk = create_sdk(tmp_path / "configured-sdk")
    explicit_sdk = create_sdk(tmp_path / "explicit-sdk")
    external_assets = create_web_assets(tmp_path / "external-assets")

    plan = make_setup_plan(
        tmp_path,
        LocalSourceConfig(sdk_scripts_dir=configured_sdk),
        sdk_scripts_dir=explicit_sdk,
        web_assets_dir=external_assets,
        force=True,
    )

    assert plan.sdk_scripts_dir == explicit_sdk
    assert plan.web_assets_external
    assert not plan.fetch_web_assets


def test_sha256_file_returns_expected_digest(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"known payload")

    assert sha256_file(path) == "5682cf8bc4b549d2f5f79101d03dbe613127ce4161a9bce7829dd1630a8f66d8"
    assert sha256_file(path) != "0" * 64


def test_zip_validation_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../DepotDownloader", b"not a binary")

    with zipfile.ZipFile(archive) as bundle, pytest.raises(
        SourceConfigurationError, match="unexpected contents|unsafe path"
    ):
        validate_zip_members(bundle, DEPOTDOWNLOADER_PINS["linux-x64"])
