#!/usr/bin/env python3
"""Capture two-session WebAdmin chat visibility and cursor behavior."""

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

MARKERS = ("a1", "a2", "b1", "b2")


def renamed(captures: list[Capture], prefix: str) -> list[Capture]:
    return [replace(capture, name=f"{prefix}-{capture.name}") for capture in captures]


def run(args: ToolArguments) -> int:
    """Capture the same received chat history from two isolated sessions."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probes: list[WebAdminProbe] = []
    try:
        logger.info("polling human chat markers from two independent sessions")
        for prefix in ("chat-a", "chat-b"):
            probe = WebAdminProbe(args.base_url, args.username, args.password)
            probes.append(probe)
            captures.extend(renamed(probe.login(), prefix))
            captures.append(probe.request(f"{prefix}-page", "current/chat"))
            first_poll = probe.request(
                f"{prefix}-first-poll", "current/chat/data", {"ajax": "1"}
            )
            captures.append(first_poll)
            missing = [marker for marker in MARKERS if marker not in first_poll.body]
            if missing:
                failures.append(
                    {
                        "route": f"{prefix}-first-poll",
                        "error": "one or more expected human chat markers were absent",
                    }
                )
            captures.append(
                probe.request(
                    f"{prefix}-second-poll", "current/chat/data", {"ajax": "1"}
                )
            )
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-session-chat", "error": str(error)})
    finally:
        for index, probe in enumerate(probes, start=1):
            try:
                captures.append(probe.request(f"chat-session-{index}-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": f"chat-session-{index}-logout", "error": str(error)}
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
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    username: str | None,
    password: str | None,
) -> None:
    """Capture two-session WebAdmin chat visibility and cursor behavior."""
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
