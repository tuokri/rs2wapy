#!/usr/bin/env python3
"""Send controlled WebAdmin all-chat and team-chat messages for observation."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import httpx2
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import info
from probe_webadmin import task
from probe_webadmin import warn
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status


def run(args: ToolArguments) -> int:
    """Send one all-chat and one team-chat marker from WebAdmin."""
    if not args.username or not args.password:
        warn("Administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    try:
        task("Authenticating to send controlled WebAdmin chat markers")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        captures.append(probe.request("webadmin-chat-before", "current/chat"))
        task("Sending WebAdmin all-chat marker")
        captures.append(
            probe.request(
                "webadmin-chat-all",
                "current/chat",
                {"message": "wa", "teamsay": "-1"},
            )
        )
        task("Sending WebAdmin team-chat marker")
        captures.append(
            probe.request(
                "webadmin-chat-team", "current/chat", {"message": "wt", "teamsay": "0"}
            )
        )
        captures.append(probe.request("webadmin-chat-after", "current/chat"))
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "webadmin-chat", "error": str(error)})
    finally:
        if probe is not None:
            try:
                captures.append(probe.request("webadmin-chat-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "webadmin-chat-logout", "error": str(error)})

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(args.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    if failures:
        for failure in failures:
            warn(f"{failure['route']}: {failure['error']}")
        return 1
    info(f"Wrote {len(entries)} sanitized captures to {args.output}")
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    username: str | None,
    password: str | None,
) -> None:
    """Send controlled WebAdmin all-chat and team-chat messages for observation."""
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
