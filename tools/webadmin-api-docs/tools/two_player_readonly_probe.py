#!/usr/bin/env python3
"""Capture two-player read-only state from independent WebAdmin sessions."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import click
import httpx2
from player_action_probe import player_details
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger


def renamed(captures: list[Capture], prefix: str) -> list[Capture]:
    return [replace(capture, name=f"{prefix}-{capture.name}") for capture in captures]


def run(args: ToolArguments) -> int:
    """Capture player, squad, and chat reads without changing server state."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2
    if not args.player_name or not args.second_player_name:
        logger.warning("two controlled player names are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probes: list[WebAdminProbe] = []
    try:
        logger.info("creating two independent authenticated WebAdmin sessions")
        for prefix in ("session-a", "session-b"):
            probe = WebAdminProbe(args.base_url, args.username, args.password)
            probes.append(probe)
            captures.extend(renamed(probe.login(), prefix))
            current = probe.request(f"{prefix}-current", "current")
            players = probe.request(f"{prefix}-players", "current/players")
            player_details(players, args.player_name)
            player_details(players, args.second_player_name)
            captures.extend(
                [
                    current,
                    players,
                    probe.request(f"{prefix}-squads", "current/squads"),
                    probe.request(f"{prefix}-chat", "current/chat"),
                    probe.request(
                        f"{prefix}-chat-data-baseline",
                        "current/chat/data",
                        {"ajax": "1"},
                    ),
                ]
            )
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-player-readonly", "error": str(error)})
    finally:
        for index, probe in enumerate(probes, start=1):
            try:
                captures.append(probe.request(f"session-{index}-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": f"session-{index}-logout", "error": str(error)}
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
@click.option("--player-name", required=True, help="First controlled player name")
@click.option("--second-player-name", required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    player_name: str,
    second_player_name: str,
    username: str | None,
    password: str | None,
) -> None:
    """Capture two-player read-only state from independent WebAdmin sessions."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                player_name=player_name,
                second_player_name=second_player_name,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
