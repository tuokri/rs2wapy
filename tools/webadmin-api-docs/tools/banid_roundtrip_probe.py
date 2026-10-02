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

"""Exercise one permanent player-ID ban and mandatory revocation."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
from player_action_probe import player_action
from player_action_probe import player_details
from player_action_probe import revoke_permanent_ban
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
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe = WebAdminProbe(args.base_url, args.username, args.password)
    unique_id = ""
    ban_submitted = False
    try:
        logger.info("authenticating for the permanent ID-ban round trip")
        captures.extend(probe.login())
        players = probe.request("banid-before-players", "current/players")
        captures.append(players)
        player_key, unique_id = player_details(players, args.player_name)
        bans_before = probe.request("banid-before-policy", "policy/bans")
        captures.append(bans_before)
        if unique_id in bans_before.body:
            raise RuntimeError("target already has a permanent ID ban")

        logger.info("submitting one permanent ID ban")
        ban_submitted = True
        captures.append(
            player_action(
                probe,
                "banid-submit",
                "banid",
                player_key,
                {
                    "__Reason": "RS2 WebAdmin documentation probe",
                    "__ExpNumber": "1",
                    "__ExpUnit": "Never",
                    "__NotifyPlayers": "0",
                },
            )
        )
        bans_after = probe.request("banid-after-policy", "policy/bans")
        captures.append(bans_after)
        if unique_id not in bans_after.body:
            raise RuntimeError("banid did not create a permanent ID ban")
    except (OSError, RuntimeError) as error:
        failures.append({"route": "banid-roundtrip", "error": str(error)})
    finally:
        if ban_submitted and unique_id:
            try:
                captures.extend(revoke_permanent_ban(probe, unique_id))
            except (OSError, RuntimeError) as error:
                failures.append({"route": "banid-revoke", "error": str(error)})
        try:
            captures.append(probe.request("banid-logout", "logout"))
        except OSError as error:
            failures.append({"route": "banid-logout", "error": str(error)})

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(probe.base_url)
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
    """Exercise one permanent player-ID ban and mandatory revocation."""
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
