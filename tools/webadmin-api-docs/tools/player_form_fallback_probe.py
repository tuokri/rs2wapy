#!/usr/bin/env python3
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
from probe_webadmin import info
from probe_webadmin import task
from probe_webadmin import warn
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status


def run(args: ToolArguments) -> int:
    """Change tracking through POST /current/players and restore its baseline."""
    if not args.username or not args.password:
        warn("Administrator credentials are required")
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
        task("Authenticating for the Current Players form fallback probe")
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

        task("Submitting a tracking action through POST /current/players")
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
                info("Form action did not establish an observable tracking transition")
            else:
                info("Form action established an observable tracking transition")
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
                    task("Restoring tracking baseline through POST /current/players")
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
            warn(f"{failure['route']}: {failure['error']}")
        return 1
    info(f"Wrote {len(entries)} sanitized captures to {args.output}")
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
