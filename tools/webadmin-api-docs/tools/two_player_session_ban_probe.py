#!/usr/bin/env python3
"""Session-ban one authorized player while verifying a second remains connected."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import httpx2
from player_action_probe import player_action
from player_action_probe import player_details
from player_action_probe import revoke_session_ban
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
    """Session-ban the target, revoke it, and verify the observer stays online."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2
    if not args.player_name or not args.second_player_name:
        logger.warning("target and observer player names are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    unique_id = ""
    submitted = False
    try:
        logger.info("authenticating for the two-player session-ban probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("two-player-session-ban-before", "current/players")
        captures.append(before)
        player_key, unique_id = player_details(before, args.player_name)
        player_details(before, args.second_player_name)
        session_before = probe.request(
            "two-player-session-bans-before", "policy/session"
        )
        captures.append(session_before)
        if unique_id in session_before.body:
            raise RuntimeError("target already has a session ban")

        logger.info("submitting temporary session ban")
        submitted = True
        captures.append(
            player_action(
                probe,
                "two-player-session-ban-action",
                "sessionban",
                player_key,
                {
                    "__Reason": "RS2 WebAdmin documentation probe",
                    "__NotifyPlayers": "0",
                },
            )
        )
        after_action = probe.request(
            "two-player-session-ban-after-action", "current/players"
        )
        captures.append(after_action)
        if args.player_name in after_action.body:
            raise RuntimeError("session ban did not disconnect the controlled target")
        player_details(after_action, args.second_player_name)
        session_after = probe.request(
            "two-player-session-bans-after-action", "policy/session"
        )
        captures.append(session_after)
        if unique_id not in session_after.body:
            raise RuntimeError("session-ban action did not create a session-ban record")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-player-session-ban", "error": str(error)})
    finally:
        if probe is not None and submitted:
            try:
                captures.extend(revoke_session_ban(probe, unique_id))
                after_revoke = probe.request(
                    "two-player-session-ban-after-revoke", "current/players"
                )
                captures.append(after_revoke)
                player_details(after_revoke, args.second_player_name)
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "two-player-session-ban-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("two-player-session-ban-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "two-player-session-ban-logout", "error": str(error)}
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
@click.option("--player-name", required=True, help="Authorized player to session-ban")
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
    """Capture a temporary two-player session-ban/revoke sequence."""
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
