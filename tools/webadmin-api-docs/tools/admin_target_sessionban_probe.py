#!/usr/bin/env python3

# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Verify that a logged-in-game administrator cannot receive a session ban."""

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
    """Capture the protected session-ban branch and clean up unexpected state."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2
    if not args.player_name or not args.second_player_name:
        logger.warning("admin target and controlled observer are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    unique_id = ""
    submitted = False
    try:
        logger.info("authenticating for the protected session-ban probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        players_before = probe.request(
            "admin-sessionban-before-players", "current/players"
        )
        captures.append(players_before)
        player_key, unique_id = player_details(players_before, args.player_name)
        player_details(players_before, args.second_player_name)
        session_before = probe.request(
            "admin-sessionban-before-session-bans", "policy/session"
        )
        captures.append(session_before)
        if unique_id in session_before.body:
            raise RuntimeError("administrator target already has a session ban")

        logger.info(
            "submitting browser-shaped session ban against logged administrator"
        )
        submitted = True
        action = player_action(
            probe,
            "admin-sessionban-action",
            "sessionban",
            player_key,
            {
                "__Reason": "RS2 WebAdmin documentation probe",
                "__NotifyPlayers": "0",
            },
        )
        captures.append(action)
        players_after = probe.request(
            "admin-sessionban-after-players", "current/players"
        )
        session_after = probe.request(
            "admin-sessionban-after-session-bans", "policy/session"
        )
        captures.extend([players_after, session_after])
        player_details(players_after, args.player_name)
        player_details(players_after, args.second_player_name)
        if "<nop" not in action.body:
            raise RuntimeError("protected session-ban action did not return nop")
        if unique_id in session_after.body:
            raise RuntimeError("protected session-ban action created a session ban")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "admin-sessionban", "error": str(error)})
    finally:
        if probe is not None and submitted and unique_id:
            try:
                session_current = probe.request(
                    "admin-sessionban-cleanup-check", "policy/session"
                )
                captures.append(session_current)
                if unique_id in session_current.body:
                    logger.warning("unexpected session ban found; revoking it")
                    captures.extend(revoke_session_ban(probe, unique_id))
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "admin-sessionban-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("admin-sessionban-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "admin-sessionban-logout", "error": str(error)}
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
@click.option("--player-name", required=True, help="Logged in-game administrator")
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
    """Verify the safe denial branch for an in-game administrator target."""
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
