#!/usr/bin/env python3
"""Capture sanitized, read-only RS2 WebAdmin MultiAdmin evidence."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from pathlib import Path

import click
import httpx2
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger


def login(
    probe: WebAdminProbe,
    name: str,
    username: str,
    password: str,
    mode: str,
    remember: str | None = None,
) -> tuple[list[Capture], bool]:
    landing = probe.request(f"{name}-login-page", "")
    token_match = re.search(
        r'<input[^>]+name=["\']token["\'][^>]+value=["\']([^"\']+)',
        landing.body,
        re.IGNORECASE,
    )
    algorithm_match = re.search(r'var\s+hashAlg\s*=\s*"([^"]*)"', landing.body)
    if not token_match or not algorithm_match:
        raise RuntimeError(
            "login page did not contain the expected authentication fields"
        )

    algorithm = algorithm_match.group(1).lower()
    if mode == "sha1":
        if algorithm != "sha1":
            raise RuntimeError(
                f"expected sha1 login mode, got {algorithm or 'plaintext'}"
            )
        password_hash = (
            f"$sha1${hashlib.sha1((password + username).encode('utf-8')).hexdigest()}"
        )
        password_value = ""
    elif mode == "plaintext":
        password_hash = ""
        password_value = password
    else:
        raise ValueError(f"unsupported login mode: {mode}")

    form = {
        "username": username,
        "password": password_value,
        "password_hash": password_hash,
        "token": token_match.group(1),
    }
    if remember is not None:
        form["remember"] = remember
    submitted = probe.request(f"{name}-login-submit", "", form)
    title_match = re.search(
        r"<title>(.*?)</title>", submitted.body, re.IGNORECASE | re.DOTALL
    )
    title = (
        html.unescape(re.sub(r"\s+", " ", title_match.group(1)).strip())
        if title_match
        else ""
    )
    return [landing, submitted], "Login" not in title


def require_args(args: ToolArguments) -> bool:
    required = (
        args.primary_username,
        args.primary_password,
        args.secondary_username,
        args.secondary_password,
        args.disabled_username,
        args.disabled_password,
    )
    if all(required):
        return True
    logger.warning("primary, secondary, and disabled account credentials are required")
    return False


def run(args: ToolArguments) -> int:
    if not require_args(args):
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    try:
        logger.info("capturing primary MultiAdmin session")
        primary = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        primary_captures, authenticated = login(
            primary,
            "primary-sha1",
            args.primary_username,
            args.primary_password,
            "sha1",
            remember="1800",
        )
        captures.extend(primary_captures)
        if not authenticated:
            raise RuntimeError("primary SHA-1 login was not authenticated")
        captures.extend(
            [
                primary.request("primary-current", "current"),
                primary.request("primary-multiadmin", "multiadmin"),
                primary.request(
                    "primary-select-secondary",
                    "multiadmin",
                    {"adminid": args.secondary_username},
                ),
                primary.request(
                    "primary-select-disabled",
                    "multiadmin",
                    {"adminid": args.disabled_username},
                ),
                primary.request("primary-logout", "logout"),
                primary.request("primary-after-logout", "current"),
            ]
        )

        logger.info("capturing plaintext login compatibility")
        plaintext = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        plaintext_captures, authenticated = login(
            plaintext,
            "primary-plaintext",
            args.primary_username,
            args.primary_password,
            "plaintext",
        )
        captures.extend(plaintext_captures)
        if not authenticated:
            failures.append(
                {"route": "plaintext-login", "error": "returned login page"}
            )
        else:
            captures.append(plaintext.request("primary-plaintext-logout", "logout"))

        logger.info("capturing secondary administrator authorization reads")
        secondary = WebAdminProbe(
            args.base_url, args.secondary_username, args.secondary_password
        )
        secondary_captures, authenticated = login(
            secondary,
            "secondary-sha1",
            args.secondary_username,
            args.secondary_password,
            "sha1",
        )
        captures.extend(secondary_captures)
        if not authenticated:
            failures.append(
                {"route": "secondary-login", "error": "returned login page"}
            )
        else:
            for route in (
                "current",
                "current/players",
                "policy",
                "settings/general",
                "console",
                "multiadmin",
            ):
                captures.append(secondary.request(f"secondary-get-{route}", route))
            captures.append(secondary.request("secondary-logout", "logout"))

        logger.info("capturing disabled-account login response")
        disabled = WebAdminProbe(
            args.base_url, args.disabled_username, args.disabled_password
        )
        disabled_captures, authenticated = login(
            disabled,
            "disabled-sha1",
            args.disabled_username,
            args.disabled_password,
            "sha1",
        )
        captures.extend(disabled_captures)
        if authenticated:
            captures.append(disabled.request("disabled-logout", "logout"))
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        logger.error("multiadmin probe error: {}", error)
        return 1

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(args.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info("wrote {} sanitized captures to '{}'", len(entries), args.output)
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--primary-username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--primary-password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
@click.option(
    "--secondary-username", default=os.environ.get("RS2_WEBADMIN_SECONDARY_USERNAME")
)
@click.option(
    "--secondary-password", default=os.environ.get("RS2_WEBADMIN_SECONDARY_PASSWORD")
)
@click.option(
    "--disabled-username", default=os.environ.get("RS2_WEBADMIN_DISABLED_USERNAME")
)
@click.option(
    "--disabled-password", default=os.environ.get("RS2_WEBADMIN_DISABLED_PASSWORD")
)
def main(
    base_url: str,
    output: Path,
    primary_username: str | None,
    primary_password: str | None,
    secondary_username: str | None,
    secondary_password: str | None,
    disabled_username: str | None,
    disabled_password: str | None,
) -> None:
    """Capture sanitized, read-only RS2 WebAdmin MultiAdmin evidence."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                primary_username=primary_username or "",
                primary_password=primary_password or "",
                secondary_username=secondary_username or "",
                secondary_password=secondary_password or "",
                disabled_username=disabled_username or "",
                disabled_password=disabled_password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
