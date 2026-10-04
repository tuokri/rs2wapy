#!/usr/bin/env python3
"""Kick one authorized player while verifying a second player remains connected."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import httpx2
from player_action_probe import player_action
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


def run(args: ToolArguments) -> int:
    """Kick a controlled target and assert that the controlled observer remains."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2
    if not args.player_name or not args.second_player_name:
        logger.warning("target and observer player names are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    try:
        logger.info("authenticating for the two-player kick probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("two-player-kick-before", "current/players")
        captures.append(before)
        player_key, _ = player_details(before, args.player_name)
        player_details(before, args.second_player_name)

        logger.info("kicking the controlled target player")
        captures.append(
            player_action(
                probe,
                "two-player-kick-action",
                "kick",
                player_key,
                {
                    "__Reason": "RS2 WebAdmin documentation probe",
                    "__NotifyPlayers": "0",
                },
            )
        )
        after = probe.request("two-player-kick-after", "current/players")
        captures.append(after)
        if args.player_name in after.body:
            raise RuntimeError("kick did not remove the controlled target player")
        player_details(after, args.second_player_name)
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-player-kick", "error": str(error)})
    finally:
        if probe is not None:
            try:
                captures.append(probe.request("two-player-kick-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "two-player-kick-logout", "error": str(error)})

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
@click.option("--player-name", required=True, help="Authorized player to kick")
@click.option("--second-player-name", required=True, help="Controlled observer that remains")
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
    """Capture a controlled kick while a second controlled player remains online."""
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
