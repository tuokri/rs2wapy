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

"""Temporarily ID-ban one authorized player while a second remains connected."""

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


def revoke_permanent_ban(probe: WebAdminProbe, unique_id: str) -> list[Capture]:
    """Revoke this probe's temporary ID ban and prove the row is gone."""
    logger.info("revoking temporary permanent ID ban")
    revoked = probe.request(
        "two-player-permanent-ban-revoke",
        "policy/bans",
        {"action": "revoke", "uniqueid": unique_id, "__Submitter": ""},
    )
    restored = probe.request(
        "two-player-permanent-bans-after-revoke", "policy/bans"
    )
    if unique_id in restored.body:
        raise RuntimeError("permanent ID ban remains after revoke")
    return [revoked, restored]


def run(args: ToolArguments) -> int:
    """ID-ban the target, revoke it, and verify the observer stays online."""
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
        logger.info("authenticating for the two-player permanent ID-ban probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("two-player-permanent-ban-before", "current/players")
        captures.append(before)
        player_key, unique_id = player_details(before, args.player_name)
        player_details(before, args.second_player_name)
        bans_before = probe.request(
            "two-player-permanent-bans-before", "policy/bans"
        )
        captures.append(bans_before)
        if unique_id in bans_before.body:
            raise RuntimeError("target already has a permanent ID ban")

        logger.info("submitting temporary permanent ID ban")
        # A transport failure has an unknown write outcome, so cleanup is armed
        # before the request is sent.
        submitted = True
        action = player_action(
            probe,
            "two-player-permanent-ban-action",
            "banid",
            player_key,
            {
                "__Reason": "RS2 WebAdmin documentation probe",
                "__ExpNumber": "1",
                "__ExpUnit": "Never",
                "__NotifyPlayers": "0",
            },
        )
        captures.append(action)
        if "<kicked" not in action.body:
            raise RuntimeError("permanent ID-ban action did not return a kicked result")
        after_action = probe.request(
            "two-player-permanent-ban-after-action", "current/players"
        )
        captures.append(after_action)
        player_details(after_action, args.second_player_name)
        bans_after = probe.request(
            "two-player-permanent-bans-after-action", "policy/bans"
        )
        captures.append(bans_after)
        if unique_id not in bans_after.body:
            raise RuntimeError("permanent ID-ban action did not create a ban record")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "two-player-permanent-ban", "error": str(error)})
    finally:
        if probe is not None and submitted:
            try:
                captures.extend(revoke_permanent_ban(probe, unique_id))
                after_revoke = probe.request(
                    "two-player-permanent-ban-after-revoke", "current/players"
                )
                captures.append(after_revoke)
                player_details(after_revoke, args.second_player_name)
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "two-player-permanent-ban-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(
                    probe.request("two-player-permanent-ban-logout", "logout")
                )
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "two-player-permanent-ban-logout", "error": str(error)}
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
@click.option("--player-name", required=True, help="Authorized player to ID-ban")
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
    """Capture a temporary two-player permanent-ID-ban/revoke sequence."""
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
