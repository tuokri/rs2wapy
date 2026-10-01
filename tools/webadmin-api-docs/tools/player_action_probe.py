#!/usr/bin/env python3
"""Exercise reversible RS2 WebAdmin player actions against a named test player."""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

import click
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import info
from webadmin_api_docs.logging import task
from webadmin_api_docs.logging import warn


def player_details(page: Capture, player_name: str) -> tuple[str, str]:
    for index, player_key in re.findall(
        r'name=["\']__PlayerKey_(\d+)["\'][^>]*value=["\']([^"\']+)',
        page.body,
        re.IGNORECASE,
    ):
        name_match = re.search(
            rf'name=["\']__PlayerName_{index}["\'][^>]*value=["\']([^"\']*)',
            page.body,
            re.IGNORECASE,
        )
        if name_match and html.unescape(name_match.group(1)) == player_name:
            unique_match = re.match(r"\d+_(0x[0-9a-f]+)_", player_key, re.IGNORECASE)
            if not unique_match:
                raise RuntimeError("player key did not contain a unique identifier")
            return player_key, unique_match.group(1)
    raise RuntimeError("named player was not present in the current-player table")


def player_action(
    probe: WebAdminProbe,
    name: str,
    action: str,
    player_key: str,
    extra: dict[str, str] | None = None,
) -> Capture:
    form = {"ajax": "1", "action": action, "playerkey": player_key}
    if extra:
        form.update(extra)
    return probe.request(name, "current/players/data", form)


def player_still_present(probe: WebAdminProbe, player_name: str) -> Capture:
    page = probe.request("player-after-action", "current/players")
    if player_name not in page.body:
        warn("Target player is no longer connected")
    return page


def revoke_session_ban(probe: WebAdminProbe, unique_id: str) -> list[Capture]:
    """Revoke and then independently confirm removal of a target session ban."""
    task("Revoking temporary session ban")
    revoked = probe.request(
        "session-ban-revoke",
        "policy/session",
        {"action": "revoke", "__UniqueId": unique_id, "__Submitter": ""},
    )
    restored = probe.request("session-bans-after-revoke", "policy/session")
    if unique_id in restored.body:
        raise RuntimeError("session ban remains after revoke")
    return [revoked, restored]


def revoke_permanent_ban(probe: WebAdminProbe, unique_id: str) -> list[Capture]:
    """Revoke and independently confirm removal of a target ID ban."""
    task("Revoking temporary permanent ID ban")
    revoked = probe.request(
        "permanent-ban-revoke",
        "policy/bans",
        {"action": "revoke", "uniqueid": unique_id, "__Submitter": ""},
    )
    restored = probe.request("permanent-bans-after-revoke", "policy/bans")
    if unique_id in restored.body:
        raise RuntimeError("permanent ID ban remains after revoke")
    return [revoked, restored]


def run(args: ToolArguments) -> tuple[list[Capture], str]:
    probe = WebAdminProbe(args.base_url, args.username, args.password)
    captures = probe.login()
    before = probe.request("player-before-actions", "current/players")
    captures.append(before)
    player_key, unique_id = player_details(before, args.player_name)

    task("Testing voice mute and unmute")
    captures.append(player_action(probe, "player-mutevoice", "mutevoice", player_key))
    captures.append(
        player_action(probe, "player-unmutevoice", "unmutevoice", player_key)
    )

    task("Testing session-ban action with mandatory cleanup")
    session_before = probe.request("session-bans-before", "policy/session")
    captures.append(session_before)
    if unique_id in session_before.body:
        raise RuntimeError(
            "target already has a session ban; refusing to alter existing state"
        )
    session_ban_submitted = False
    try:
        # Treat a transport error as an unknown write outcome. The server may
        # have processed the request before the connection was interrupted.
        session_ban_submitted = True
        captures.append(
            player_action(
                probe,
                "player-sessionban",
                "sessionban",
                player_key,
                {
                    "__Reason": "RS2 WebAdmin documentation probe",
                    "__NotifyPlayers": "0",
                },
            )
        )
        session_after = probe.request("session-bans-after-action", "policy/session")
        captures.append(session_after)
        if unique_id not in session_after.body:
            info("Session-ban action did not create a session ban")
    finally:
        # Submit the revoke even if the readback failed. This makes cleanup the
        # outcome of sending a session-ban request rather than a best-effort
        # follow-up contingent on a successful response.
        if session_ban_submitted:
            captures.extend(revoke_session_ban(probe, unique_id))

    if args.permanent_ban_roundtrip:
        task("Testing permanent ID-ban action with mandatory cleanup")
        permanent_before = probe.request("permanent-bans-before", "policy/bans")
        captures.append(permanent_before)
        if unique_id in permanent_before.body:
            raise RuntimeError(
                "target already has a permanent ID ban; refusing to alter existing state"
            )
        permanent_ban_submitted = False
        try:
            # Treat a transport error as an unknown write outcome. The server
            # may have processed the request before the connection ended.
            permanent_ban_submitted = True
            captures.append(
                player_action(
                    probe,
                    "player-banid",
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
                "permanent-bans-after-action", "policy/bans"
            )
            captures.append(permanent_after)
            if unique_id not in permanent_after.body:
                info("Permanent ID-ban action did not create a permanent ban")
        finally:
            if permanent_ban_submitted:
                captures.extend(revoke_permanent_ban(probe, unique_id))

    captures.append(player_still_present(probe, args.player_name))
    captures.append(probe.request("logout-player-actions", "logout"))
    return captures, probe.base_url


def execute(args: ToolArguments) -> int:
    if not args.username or not args.password:
        warn(
            "Username and password are required through options or environment variables"
        )
        return 2
    try:
        captures, base_url = run(args)
    except (OSError, RuntimeError) as error:
        warn(str(error))
        return 1
    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    info(f"Wrote {len(entries)} sanitized player-action captures to {args.output}")
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
    "--permanent-ban-roundtrip",
    is_flag=True,
    help="Test banid and immediately revoke it after a fresh policy-table check",
)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    player_name: str,
    permanent_ban_roundtrip: bool,
    username: str | None,
    password: str | None,
) -> None:
    """Exercise reversible RS2 WebAdmin actions against an authorized player."""
    exit_with_status(
        execute(
            ToolArguments(
                base_url=base_url,
                output=output,
                player_name=player_name,
                permanent_ban_roundtrip=permanent_ban_roundtrip,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
