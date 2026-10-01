#!/usr/bin/env python3
"""Probe a disposable MultiAdmin permission profile and restore it."""

from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class AdminProfile:
    admin_id: str
    display_name: str
    enabled: str
    order: str
    allow: str
    deny: str

    def save_form(self, enabled: str | None = None) -> dict[str, str]:
        return {
            "action": "save",
            "adminid": self.admin_id,
            "displayname": self.display_name,
            "enabled": self.enabled if enabled is None else enabled,
            "password1": "",
            "password2": "",
            "order": self.order,
            "allow": self.allow,
            "deny": self.deny,
        }


def parse_profile(body: str) -> AdminProfile:
    profile_form_match = re.search(
        r'<form\b[^>]*\bid=["\']profileform["\'][^>]*>(.*?)</form>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not profile_form_match:
        raise RuntimeError("MultiAdmin response did not contain the profile form")
    profile_form = profile_form_match.group(1)

    def field(name: str) -> str:
        match = re.search(
            rf'<input[^>]*\bname=["\']{name}["\'][^>]*\bvalue=["\']([^"\']*)',
            profile_form,
            re.IGNORECASE,
        )
        if not match:
            raise RuntimeError(f"MultiAdmin response did not contain {name}")
        return html.unescape(match.group(1))

    def textarea(name: str) -> str:
        match = re.search(
            rf'<textarea[^>]*\bname=["\']{name}["\'][^>]*>(.*?)</textarea>',
            profile_form,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            raise RuntimeError(f"MultiAdmin response did not contain {name}")
        return html.unescape(match.group(1))

    enabled_match = re.search(
        r'<input[^>]*\bname=["\']enabled["\'][^>]*\bvalue=["\']([01])["\'][^>]*checked=',
        profile_form,
        re.IGNORECASE,
    )
    order_match = re.search(
        r'<input[^>]*\bname=["\']order["\'][^>]*\bvalue=["\']([^"\']+)["\'][^>]*checked=',
        profile_form,
        re.IGNORECASE,
    )
    if not enabled_match or not order_match:
        raise RuntimeError(
            "MultiAdmin response did not contain selected profile settings"
        )
    return AdminProfile(
        admin_id=field("adminid"),
        display_name=field("displayname"),
        enabled=enabled_match.group(1),
        order=order_match.group(1),
        allow=textarea("allow"),
        deny=textarea("deny"),
    )


def run(args: ToolArguments) -> int:
    if not all(
        (
            args.primary_username,
            args.primary_password,
            args.restricted_username,
            args.restricted_password,
        )
    ):
        logger.warning("primary and restricted account credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    baseline: AdminProfile | None = None
    primary: WebAdminProbe | None = None
    enabled = False
    restoration_verified = False
    try:
        logger.info("authenticating recovery administrator")
        primary = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        login_captures, authenticated = login(
            primary,
            "permission-primary",
            args.primary_username,
            args.primary_password,
            "sha1",
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("recovery administrator login was not authenticated")

        selected = primary.request(
            "permission-baseline-profile",
            "multiadmin",
            {"adminid": args.restricted_username},
        )
        captures.append(selected)
        baseline = parse_profile(selected.body)
        if baseline.enabled != "0":
            raise RuntimeError(
                "restricted account was not disabled at the expected baseline"
            )

        logger.info("enabling disposable restricted administrator")
        captures.append(
            primary.request(
                "permission-enable", "multiadmin", baseline.save_form(enabled="1")
            )
        )
        enabled = True

        logger.info("capturing restricted administrator reads")
        restricted = WebAdminProbe(
            args.base_url, args.restricted_username, args.restricted_password
        )
        login_captures, authenticated = login(
            restricted,
            "permission-restricted",
            args.restricted_username,
            args.restricted_password,
            "sha1",
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("enabled restricted account login was not authenticated")
        for name, route in (
            ("permission-allowed-current", "current"),
            ("permission-allowed-session-bans", "policy/session"),
            ("permission-allowed-welcome", "settings/general/welcome"),
            ("permission-denied-gametypes", "settings/gametypes"),
            ("permission-denied-multiadmin", "multiadmin"),
        ):
            captures.append(restricted.request(name, route))

        logger.info("disabling disposable restricted administrator")
        captures.append(
            primary.request("permission-disable", "multiadmin", baseline.save_form())
        )
        enabled = False
        captures.append(
            restricted.request("permission-restricted-after-disable", "current")
        )
        restored = primary.request(
            "permission-restored-profile",
            "multiadmin",
            {"adminid": args.restricted_username},
        )
        captures.append(restored)
        if parse_profile(restored.body) != baseline:
            failures.append(
                {
                    "route": "permission-restore",
                    "error": "restored profile differs from baseline",
                }
            )
        restoration_verified = True
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "permission-probe", "error": str(error)})
    finally:
        if enabled and primary is not None and baseline is not None:
            try:
                captures.append(
                    primary.request(
                        "permission-disable", "multiadmin", baseline.save_form()
                    )
                )
                enabled = False
            except (
                OSError,
                RuntimeError,
                httpx2.RequestError,
            ) as error:
                failures.append({"route": "permission-restore", "error": str(error)})
        if primary is not None and baseline is not None and not restoration_verified:
            try:
                restored = primary.request(
                    "permission-restored-profile",
                    "multiadmin",
                    {"adminid": args.restricted_username},
                )
                captures.append(restored)
                if parse_profile(restored.body) != baseline:
                    failures.append(
                        {
                            "route": "permission-restore",
                            "error": "restored profile differs from baseline",
                        }
                    )
            except (
                OSError,
                RuntimeError,
                httpx2.RequestError,
            ) as error:
                failures.append({"route": "permission-restore", "error": str(error)})
        if primary is not None:
            try:
                captures.append(primary.request("permission-primary-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "permission-primary-logout", "error": str(error)}
                )

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(args.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    if failures:
        for failure in failures:
            logger.warning("{}: {}", failure["route"], failure["error"])
        return 1
    logger.info("wrote {} sanitized captures to '{}'", len(entries), args.output)
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--primary-username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--primary-password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
@click.option(
    "--restricted-username", default=os.environ.get("RS2_WEBADMIN_DISABLED_USERNAME")
)
@click.option(
    "--restricted-password", default=os.environ.get("RS2_WEBADMIN_DISABLED_PASSWORD")
)
def main(
    base_url: str,
    output: Path,
    primary_username: str | None,
    primary_password: str | None,
    restricted_username: str | None,
    restricted_password: str | None,
) -> None:
    """Probe a disposable MultiAdmin permission profile and restore it."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                primary_username=primary_username or "",
                primary_password=primary_password or "",
                restricted_username=restricted_username or "",
                restricted_password=restricted_password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
