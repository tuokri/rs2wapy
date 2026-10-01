#!/usr/bin/env python3
"""Exercise a kick and a temporary permanent-ID-ban against one authorized player."""

from __future__ import annotations

import json
import os
import time
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


def wait_for_player(
    probe: WebAdminProbe, player_name: str, phase: str, wait_seconds: int
) -> tuple[list[Capture], str, str]:
    """Poll the players page until the authorized player reconnects."""
    deadline = time.monotonic() + wait_seconds
    captures: list[Capture] = []
    attempt = 0
    while True:
        attempt += 1
        page = probe.request(f"{phase}-reconnect-poll-{attempt}", "current/players")
        captures.append(page)
        try:
            player_key, unique_id = player_details(page, player_name)
            return captures, player_key, unique_id
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"target did not reconnect within {wait_seconds} seconds"
                )
            logger.info("waiting for target player to reconnect")
            time.sleep(3)


def wait_for_disconnect(probe: WebAdminProbe, player_name: str) -> list[Capture]:
    """Confirm that a requested kick disconnected the controlled player."""
    captures: list[Capture] = []
    for attempt in range(1, 6):
        page = probe.request(f"kick-disconnect-poll-{attempt}", "current/players")
        captures.append(page)
        try:
            player_details(page, player_name)
        except RuntimeError:
            return captures
        time.sleep(1)
    raise RuntimeError("kick did not disconnect target; refusing to issue an ID ban")


def run(args: ToolArguments) -> tuple[list[Capture], str]:
    probe = WebAdminProbe(args.base_url, args.username, args.password)
    captures = probe.login()
    logger.info("waiting for authorized target player")
    initial, player_key, unique_id = wait_for_player(
        probe,
        args.player_name,
        "initial",
        args.wait_seconds,
    )
    captures.extend(initial)

    permanent_before = probe.request("kick-ban-permanent-bans-before", "policy/bans")
    captures.append(permanent_before)
    if unique_id in permanent_before.body:
        raise RuntimeError(
            "target already has a permanent ID ban; refusing to alter existing state"
        )

    logger.info("testing kick action")
    captures.append(
        player_action(
            probe,
            "player-kick",
            "kick",
            player_key,
            {"__Reason": "RS2 WebAdmin documentation probe", "__NotifyPlayers": "0"},
        )
    )
    captures.extend(wait_for_disconnect(probe, args.player_name))

    logger.info("waiting for reconnect after kick")
    reconnected, player_key, reconnected_unique_id = wait_for_player(
        probe,
        args.player_name,
        "after-kick",
        args.wait_seconds,
    )
    captures.extend(reconnected)
    if reconnected_unique_id != unique_id:
        raise RuntimeError(
            "reconnected player did not have the expected unique identifier"
        )

    logger.info("testing permanent ID-ban action with mandatory cleanup")
    permanent_ban_submitted = False
    try:
        # A connection failure after sending this request has an unknown write
        # outcome, so cleanup is armed before the request is made.
        permanent_ban_submitted = True
        captures.append(
            player_action(
                probe,
                "player-banid-permanent",
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
        permanent_after = probe.request(
            "kick-ban-permanent-bans-after-action", "policy/bans"
        )
        captures.append(permanent_after)
        if unique_id not in permanent_after.body:
            raise RuntimeError("permanent ID-ban action did not create a ban record")
    finally:
        if permanent_ban_submitted:
            captures.extend(revoke_permanent_ban(probe, unique_id))

    logger.info("waiting for reconnect after permanent ID-ban revoke")
    restored, restored_key, restored_unique_id = wait_for_player(
        probe,
        args.player_name,
        "after-permanent-ban",
        args.wait_seconds,
    )
    captures.extend(restored)
    if restored_unique_id != unique_id or not restored_key:
        raise RuntimeError("reconnected player did not match the revoked ID-ban target")
    captures.append(probe.request("logout-kick-ban-actions", "logout"))
    return captures, probe.base_url


def execute(args: ToolArguments) -> int:
    if args.wait_seconds < 1:
        logger.warning("wait seconds must be positive")
        return 2
    if not args.username or not args.password:
        logger.warning(
            "username and password are required through options or environment variables"
        )
        return 2
    try:
        captures, base_url = run(args)
    except (OSError, RuntimeError) as error:
        logger.error("kick/ban probe error: {}", error)
        return 1
    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info("wrote {} sanitized kick/ban captures to '{}'", len(entries), args.output)
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True, help="WebAdmin base URL")
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    required=True,
    help="Directory for sanitized captures",
)
@click.option(
    "--player-name", required=True, help="Connected player authorized for testing"
)
@click.option(
    "--wait-seconds",
    type=click.IntRange(min=1),
    default=54,
    show_default=True,
    help="Maximum wait for each player reconnection phase",
)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    player_name: str,
    wait_seconds: int,
    username: str | None,
    password: str | None,
) -> None:
    """Exercise a kick and permanent-ID-ban against one authorized player."""
    configure_logging()
    exit_with_status(
        execute(
            ToolArguments(
                base_url=base_url,
                output=output,
                player_name=player_name,
                wait_seconds=wait_seconds,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
