#!/usr/bin/env python3
"""Capture harmless management-console submissions for log correlation."""

from __future__ import annotations

import json
import os
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

COMMANDS = ("help", "status", "version")


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    try:
        logger.info("authenticating for harmless console submissions")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        login_captures, authenticated = login(
            probe, "console-log", args.username, args.password, "sha1"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")
        captures.append(probe.request("console-log-baseline", "console"))
        logger.info("submitting documented harmless console commands")
        for command in COMMANDS:
            captures.append(
                probe.request(f"console-log-{command}", "console", {"command": command})
            )
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "console-log", "error": str(error)})
    finally:
        if probe is not None:
            try:
                captures.append(probe.request("console-log-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "console-log-logout", "error": str(error)})

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
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str, output: Path, username: str | None, password: str | None
) -> None:
    """Capture harmless management-console submissions for log correlation."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
