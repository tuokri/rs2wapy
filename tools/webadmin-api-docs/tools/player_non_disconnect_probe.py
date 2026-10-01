#!/usr/bin/env python3
"""Exercise reversible, non-disconnecting actions for one authorized player."""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

import click
import httpx2
from multiadmin_probe import login
from player_action_probe import player_action
from player_action_probe import player_details
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

RUN_MARKER = "mock-doc-20260926-player"


def player_actions(page: Capture, player_name: str) -> set[str]:
    for index, value in re.findall(
        r'name=["\']__PlayerName_(\d+)["\'][^>]*value=["\']([^"\']*)',
        page.body,
        re.IGNORECASE,
    ):
        if html.unescape(value) != player_name:
            continue
        select = re.search(
            rf'<select[^>]*\bname=["\']__Action_{re.escape(index)}["\'][^>]*>(.*?)</select>',
            page.body,
            re.IGNORECASE | re.DOTALL,
        )
        if not select:
            raise RuntimeError("player row did not contain an action menu")
        return set(
            re.findall(
                r'<option\s+value=["\']([^"\']+)', select.group(1), re.IGNORECASE
            )
        )
    raise RuntimeError("named player was not present in the current-player table")


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        warn("Administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    player_key = ""
    unique_id = ""
    member_created = False
    tracking_enabled = False
    try:
        task("Authenticating for reversible player actions")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        login_captures, authenticated = login(
            probe, "player-nondisconnect", args.username, args.password, "sha1"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")

        before = probe.request("player-nondisconnect-before", "current/players")
        captures.append(before)
        player_key, unique_id = player_details(before, args.player_name)
        available = player_actions(before, args.player_name)

        if "whisper" in available:
            task("Sending one controlled whisper")
            captures.append(
                player_action(
                    probe,
                    "player-whisper",
                    "whisper",
                    player_key,
                    {"__Input": RUN_MARKER},
                )
            )

        if "swapteam" in available:
            task("Swapping and restoring the controlled player's team")
            captures.append(
                player_action(probe, "player-swapteam", "swapteam", player_key)
            )
            captures.append(
                player_action(probe, "player-swapteam-restore", "swapteam", player_key)
            )

        if "enabletracking" in available:
            task("Enabling then restoring tracking")
            tracking_enabled = True
            captures.append(
                player_action(
                    probe, "player-enabletracking", "enabletracking", player_key
                )
            )
            after_enable = probe.request(
                "player-after-enabletracking", "current/players"
            )
            captures.append(after_enable)
            if "disabletracking" not in player_actions(after_enable, args.player_name):
                raise RuntimeError("tracking enable did not expose the disable action")
            captures.append(
                player_action(
                    probe, "player-disabletracking", "disabletracking", player_key
                )
            )
            after_disable = probe.request(
                "player-after-disabletracking", "current/players"
            )
            captures.append(after_disable)
            if "enabletracking" not in player_actions(after_disable, args.player_name):
                raise RuntimeError(
                    "tracking disable did not restore the baseline action"
                )
            tracking_enabled = False

        if "makemember" in available:
            task("Creating and cancelling a temporary membership")
            member_created = True
            captures.append(
                player_action(
                    probe,
                    "player-makemember",
                    "makemember",
                    player_key,
                    {"__ExpNumber": "1", "__ExpUnit": "Hour", "__IsAdmin": "0"},
                )
            )
            members_after_add = probe.request(
                "player-members-after-add", "policy/members"
            )
            captures.append(members_after_add)
            if unique_id not in members_after_add.body:
                raise RuntimeError(
                    "temporary membership did not appear in the members page"
                )
            captures.append(
                player_action(
                    probe, "player-cancelmembership", "cancelmembership", player_key
                )
            )
            members_after_cancel = probe.request(
                "player-members-after-cancel", "policy/members"
            )
            captures.append(members_after_cancel)
            if unique_id in members_after_cancel.body:
                raise RuntimeError("temporary membership remained after cancellation")
            member_created = False
        captures.append(probe.request("player-nondisconnect-after", "current/players"))
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "player-nondisconnect", "error": str(error)})
    finally:
        if probe is not None and player_key and tracking_enabled:
            try:
                captures.append(
                    player_action(
                        probe,
                        "player-disabletracking-cleanup",
                        "disabletracking",
                        player_key,
                    )
                )
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "player-tracking-cleanup", "error": str(error)}
                )
        if probe is not None and player_key and member_created:
            try:
                captures.append(
                    player_action(
                        probe,
                        "player-cancelmembership-cleanup",
                        "cancelmembership",
                        player_key,
                    )
                )
                members_final = probe.request(
                    "player-members-after-cleanup", "policy/members"
                )
                captures.append(members_final)
                if unique_id and unique_id in members_final.body:
                    failures.append(
                        {
                            "route": "player-members-cleanup",
                            "error": "membership remained after cleanup",
                        }
                    )
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "player-members-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("player-nondisconnect-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "player-nondisconnect-logout", "error": str(error)}
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
    """Exercise reversible, non-disconnecting actions for one authorized player."""
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
