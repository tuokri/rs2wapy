#!/usr/bin/env python3
"""Kick one authorized player from a role without disconnecting either player."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import httpx2
from player_action_probe import player_details
from player_non_disconnect_probe import player_actions
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
    """Use the direct form handler to kick the target from their current role."""
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
        logger.info("authenticating for the two-player role-kick form probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before_players = probe.request("two-player-role-kick-before-players", "current/players")
        captures.append(before_players)
        player_key, _ = player_details(before_players, args.player_name)
        player_details(before_players, args.second_player_name)
        if "kickfromrole" not in player_actions(before_players, args.player_name):
            raise RuntimeError("role-kick action is not available for the target")
        captures.append(
            probe.request("two-player-role-kick-before-current", "current")
        )
        captures.append(
            probe.request("two-player-role-kick-before-squads", "current/squads")
        )

        logger.info("submitting kickfromrole through POST /current/players")
        action = probe.request(
            "two-player-role-kick-action",
            "current/players",
            {"action": "kickfromrole", "playerkey": player_key},
        )
        captures.append(action)
        if "message" not in action.body.lower():
            raise RuntimeError("role-kick form response did not render a message")

        after_players = probe.request("two-player-role-kick-after-players", "current/players")
        captures.append(after_players)
        player_details(after_players, args.player_name)
        player_details(after_players, args.second_player_name)
        captures.append(probe.request("two-player-role-kick-after-current", "current"))
        captures.append(
            probe.request("two-player-role-kick-after-squads", "current/squads")
        )
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-player-role-kick", "error": str(error)})
    finally:
        if probe is not None:
            try:
                captures.append(probe.request("two-player-role-kick-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "two-player-role-kick-logout", "error": str(error)})

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
@click.option("--player-name", required=True, help="Authorized player to remove from role")
@click.option("--second-player-name", required=True, help="Controlled observer")
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
    """Capture a direct-form role kick with two controlled players present."""
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
