#!/usr/bin/env python3
"""Probe the non-JavaScript Current Players membership form action safely."""

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
    """Create a temporary membership through the form endpoint and revoke it."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    player_key = ""
    unique_id = ""
    submitted_membership = False
    player_connected = True
    membership_created = False

    try:
        logger.info("authenticating for the Current Players membership form probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        before = probe.request("form-membership-before-players", "current/players")
        members_before = probe.request(
            "form-membership-before-members", "policy/members"
        )
        captures.extend([before, members_before])
        player_key, unique_id = player_details(before, args.player_name)
        if unique_id in members_before.body:
            raise RuntimeError(
                "controlled player is already a member; refusing to change baseline"
            )
        if "makemember" not in player_actions(before, args.player_name):
            raise RuntimeError("membership creation action is not available")

        logger.info("submitting makemember through POST /current/players")
        submitted_membership = True
        captures.append(
            probe.request(
                "form-membership-create",
                "current/players",
                {
                    "action": "makemember",
                    "playerkey": player_key,
                    "__ExpNumber": "1",
                    "__ExpUnit": "Hour",
                    "__IsAdmin": "0",
                },
            )
        )
        after_create = probe.request(
            "form-membership-after-create-players", "current/players"
        )
        members_after_create = probe.request(
            "form-membership-after-create-members", "policy/members"
        )
        captures.extend([after_create, members_after_create])
        player_connected = args.player_name in after_create.body
        if not player_connected:
            failures.append(
                {
                    "route": "current/players",
                    "error": "extended form action disconnected the controlled player",
                }
            )
        elif (
            unique_id in members_after_create.body
            and "cancelmembership" in player_actions(after_create, args.player_name)
        ):
            membership_created = True
            logger.info("form action established temporary membership")
        else:
            logger.info("form action did not establish observable membership state")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "form-membership", "error": str(error)})
    finally:
        if (
            probe is not None
            and submitted_membership
            and player_key
            and membership_created
        ):
            try:
                logger.info("restoring membership baseline through POST /current/players")
                captures.append(
                    probe.request(
                        "form-membership-cancel",
                        "current/players",
                        {"action": "cancelmembership", "playerkey": player_key},
                    )
                )
                final_players = probe.request(
                    "form-membership-final-players", "current/players"
                )
                final_members = probe.request(
                    "form-membership-final-members", "policy/members"
                )
                captures.extend([final_players, final_members])
                if unique_id in final_members.body:
                    failures.append(
                        {
                            "route": "policy/members",
                            "error": "membership remained after cleanup",
                        }
                    )
                elif (
                    args.player_name not in final_players.body
                    or "makemember"
                    not in player_actions(final_players, args.player_name)
                ):
                    failures.append(
                        {
                            "route": "current/players",
                            "error": "player action menu did not return to its membership baseline",
                        }
                    )
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "form-membership-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("form-membership-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "form-membership-logout", "error": str(error)}
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
    """Probe the non-JavaScript Current Players membership form action safely."""
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
