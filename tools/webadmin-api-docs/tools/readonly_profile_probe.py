#!/usr/bin/env python3
"""Capture sanitized, non-mutating RS2 WebAdmin profile evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import click
import httpx2
from multiadmin_probe import login
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger


def add_unauthenticated_captures(probe: WebAdminProbe) -> list[Capture]:
    captures = [
        probe.request("unauth-current", "current"),
        probe.request("unauth-multiadmin", "multiadmin"),
        probe.request("unauth-settings", "settings/general"),
        probe.request("unauth-unknown-child", "unknown-child"),
    ]

    landing = probe.request("auth-boundary-login-page", "")
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
    captures.append(landing)
    captures.append(
        probe.request(
            "auth-empty-fields",
            "",
            {
                "username": "",
                "password": "",
                "password_hash": "",
                "token": token_match.group(1),
            },
        )
    )
    return captures


def add_missing_token_capture(
    probe: WebAdminProbe, username: str, password: str
) -> list[Capture]:
    landing = probe.request("auth-missing-token-login-page", "")
    algorithm_match = re.search(r'var\s+hashAlg\s*=\s*"([^"]*)"', landing.body)
    if not algorithm_match or algorithm_match.group(1).lower() != "sha1":
        raise RuntimeError("login page did not advertise SHA-1 authentication")
    password_hash = (
        f"$sha1${hashlib.sha1((password + username).encode('utf-8')).hexdigest()}"
    )
    submitted = probe.request(
        "auth-missing-token",
        "",
        {"username": username, "password": "", "password_hash": password_hash},
    )
    return [landing, submitted]


def run(args: ToolArguments) -> int:
    if not all(
        (
            args.primary_username,
            args.primary_password,
            args.secondary_username,
            args.secondary_password,
        )
    ):
        logger.warning("primary and secondary account credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    try:
        logger.info("capturing unauthenticated and validation boundaries")
        anonymous = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        captures.extend(add_unauthenticated_captures(anonymous))
        captures.extend(
            add_missing_token_capture(
                anonymous, args.primary_username, args.primary_password
            )
        )

        logger.info("capturing independent authenticated sessions")
        first = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        first_captures, authenticated = login(
            first,
            "session-primary",
            args.primary_username,
            args.primary_password,
            "sha1",
        )
        captures.extend(first_captures)
        if not authenticated:
            raise RuntimeError("primary session login was not authenticated")
        captures.append(first.request("session-primary-current", "current"))

        second = WebAdminProbe(
            args.base_url, args.secondary_username, args.secondary_password
        )
        second_captures, authenticated = login(
            second,
            "session-secondary",
            args.secondary_username,
            args.secondary_password,
            "sha1",
        )
        captures.extend(second_captures)
        if not authenticated:
            raise RuntimeError("secondary session login was not authenticated")
        captures.append(second.request("session-secondary-current", "current"))

        captures.extend(
            [
                first.request("session-primary-logout", "logout"),
                first.request("session-primary-after-logout", "current"),
                second.request("session-secondary-after-primary-logout", "current"),
            ]
        )

        logger.info("capturing read-only selector and route behavior")
        selector = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        selector_captures, authenticated = login(
            selector, "selector", args.primary_username, args.primary_password, "sha1"
        )
        captures.extend(selector_captures)
        if not authenticated:
            raise RuntimeError("selector session login was not authenticated")
        for name, route in (
            ("data-gametypes", "data?type=gametypes"),
            (
                "data-maps-current-gametype",
                "data?type=maps&gametype=ROGame.ROGameInfoTerritories",
            ),
            (
                "data-mutators-current-gametype",
                "data?type=mutators&gametype=ROGame.ROGameInfoTerritories",
            ),
            ("data-maps-missing-gametype", "data?type=maps"),
            ("data-unknown-type", "data?type=unknown"),
            ("protected-trailing-slash", "current/"),
            ("protected-unknown-child", "current/unknown-child"),
        ):
            captures.append(selector.request(name, route))
        captures.append(selector.request("selector-logout", "logout"))
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        logger.error("read-only profile probe error: {}", error)
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
def main(
    base_url: str,
    output: Path,
    primary_username: str | None,
    primary_password: str | None,
    secondary_username: str | None,
    secondary_password: str | None,
) -> None:
    """Capture sanitized, non-mutating RS2 WebAdmin profile evidence."""
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
            )
        )
    )


if __name__ == "__main__":
    main()
