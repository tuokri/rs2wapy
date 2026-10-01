#!/usr/bin/env python3
"""Hold two chat sessions open across a human marker-send checkpoint."""

from __future__ import annotations

import json
import os
from dataclasses import replace
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

ALL_CHAT_MARKERS = ("a1", "b1")
TEAM_CHAT_MARKERS = ("a2", "b2")


def renamed(captures: list[Capture], prefix: str) -> list[Capture]:
    return [replace(capture, name=f"{prefix}-{capture.name}") for capture in captures]


def run(args: ToolArguments) -> int:
    """Create cursors, wait for markers, and then capture both poll sequences."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probes: list[tuple[str, WebAdminProbe]] = []
    try:
        logger.info("establishing two independent chat cursors")
        for prefix in ("chat-a", "chat-b"):
            probe = WebAdminProbe(args.base_url, args.username, args.password)
            probes.append((prefix, probe))
            captures.extend(renamed(probe.login(), prefix))
            captures.append(probe.request(f"{prefix}-page", "current/chat"))
            captures.append(
                probe.request(
                    f"{prefix}-baseline-poll", "current/chat/data", {"ajax": "1"}
                )
            )

        logger.info("chat cursors are ready; waiting for the human marker checkpoint")
        input()

        logger.info("polling marker visibility and cursor advancement")
        for prefix, probe in probes:
            first_poll = probe.request(
                f"{prefix}-marker-poll", "current/chat/data", {"ajax": "1"}
            )
            captures.append(first_poll)
            if any(marker not in first_poll.body for marker in ALL_CHAT_MARKERS):
                failures.append(
                    {
                        "route": f"{prefix}-marker-poll",
                        "error": "one or more expected all-chat markers were absent",
                    }
                )
            elif any(marker not in first_poll.body for marker in TEAM_CHAT_MARKERS):
                logger.info("team-chat markers were not visible in the WebAdmin chat poll")
            captures.append(
                probe.request(
                    f"{prefix}-post-marker-poll", "current/chat/data", {"ajax": "1"}
                )
            )
    except (EOFError, OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-session-chat-wait", "error": str(error)})
    finally:
        for prefix, probe in probes:
            try:
                captures.append(probe.request(f"{prefix}-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": f"{prefix}-logout", "error": str(error)})

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
    base_url: str,
    output: Path,
    username: str | None,
    password: str | None,
) -> None:
    """Hold two chat sessions open across a human marker-send checkpoint."""
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
