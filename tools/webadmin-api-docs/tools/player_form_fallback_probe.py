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

"""Probe the non-JavaScript Current Players tracking form action safely."""

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
    """Change tracking through POST /current/players and restore its baseline."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    player_key = ""
    unique_id = ""
    submitted_action = False
    player_connected = True
    baseline_tracked = False
    action = ""
    restore_action = ""
    restore_needed = False

    try:
        logger.info("authenticating for the Current Players form fallback probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        before = probe.request("form-fallback-before-players", "current/players")
        tracking_before = probe.request(
            "form-fallback-before-tracking", "policy/tracking"
        )
        captures.extend([before, tracking_before])
        player_key, unique_id = player_details(before, args.player_name)
        baseline_tracked = unique_id in tracking_before.body
        action, restore_action = (
            ("disabletracking", "enabletracking")
            if baseline_tracked
            else ("enabletracking", "disabletracking")
        )
        if action not in player_actions(before, args.player_name):
            raise RuntimeError("the expected tracking action is not available")

        logger.info("submitting a tracking action through POST /current/players")
        submitted_action = True
        captures.append(
            probe.request(
                "form-fallback-tracking-action",
                "current/players",
                {"action": action, "playerkey": player_key},
            )
        )

        after_action = probe.request(
            "form-fallback-after-action-players", "current/players"
        )
        tracking_after_action = probe.request(
            "form-fallback-after-action-tracking", "policy/tracking"
        )
        captures.extend([after_action, tracking_after_action])
        player_connected = args.player_name in after_action.body
        if not player_connected:
            failures.append(
                {
                    "route": "current/players",
                    "error": "extended form action disconnected the controlled player",
                }
            )
        else:
            after_tracked = unique_id in tracking_after_action.body
            after_actions = player_actions(after_action, args.player_name)
            restore_needed = (
                after_tracked != baseline_tracked or restore_action in after_actions
            )
            if after_tracked == baseline_tracked or restore_action not in after_actions:
                logger.info("form action did not establish an observable tracking transition")
            else:
                logger.info("form action established an observable tracking transition")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "form-fallback", "error": str(error)})
    finally:
        if (
            probe is not None
            and submitted_action
            and player_key
            and player_connected
            and restore_needed
        ):
            try:
                current = probe.request(
                    "form-fallback-before-cleanup", "current/players"
                )
                captures.append(current)
                if (
                    args.player_name in current.body
                    and restore_action in player_actions(current, args.player_name)
                ):
                    logger.info("restoring tracking baseline through POST /current/players")
                    captures.append(
                        probe.request(
                            "form-fallback-tracking-restore",
                            "current/players",
                            {"action": restore_action, "playerkey": player_key},
                        )
                    )
                    final_players = probe.request(
                        "form-fallback-final-players", "current/players"
                    )
                    final_tracking = probe.request(
                        "form-fallback-final-tracking", "policy/tracking"
                    )
                    captures.extend([final_players, final_tracking])
                    final_tracked = unique_id in final_tracking.body
                    if final_tracked != baseline_tracked:
                        failures.append(
                            {
                                "route": "policy/tracking",
                                "error": "tracking state remained after cleanup",
                            }
                        )
                    elif (
                        args.player_name not in final_players.body
                        or action not in player_actions(final_players, args.player_name)
                    ):
                        failures.append(
                            {
                                "route": "current/players",
                                "error": "player action menu did not return to its tracking baseline",
                            }
                        )
                else:
                    failures.append(
                        {
                            "route": "current/players",
                            "error": "tracking cleanup action was not available",
                        }
                    )
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append({"route": "form-fallback-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("form-fallback-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "form-fallback-logout", "error": str(error)})

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
@click.option("--player-name", required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    player_name: str,
    username: str | None,
    password: str | None,
) -> None:
    """Probe the non-JavaScript Current Players tracking form action safely."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                player_name=player_name,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
