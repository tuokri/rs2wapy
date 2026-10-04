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

"""Validate the RS2 WebAdmin documentation capture set without dependencies."""

from __future__ import annotations

import json
import re
from pathlib import Path

import click

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CAPTURE_DIRS = (
    FIXTURES / "capture",
    FIXTURES / "policy-roundtrip",
    FIXTURES / "player-actions",
    FIXTURES / "kick-ban-actions",
    FIXTURES / "multiadmin-sha1",
    FIXTURES / "multiadmin-sha1-authz",
    FIXTURES / "multiadmin-readonly",
    FIXTURES / "multiadmin-permissions",
    FIXTURES / "multiadmin-empty-state",
    FIXTURES / "phase3-core",
    FIXTURES / "phase3-travel-roundtrip",
    FIXTURES / "phase3-policy-validation-roundtrip",
    FIXTURES / "phase3-welcome-settings",
    FIXTURES / "phase3-console-log",
    FIXTURES / "phase4-player-readonly",
    FIXTURES / "phase4-player-actions",
    FIXTURES / "phase4-banid-roundtrip",
    FIXTURES / "phase4-post-banid-reconnect",
    FIXTURES / "phase4-player-form-membership",
    FIXTURES / "phase4-tracking-alias-roundtrip",
    FIXTURES / "phase4-tracking-note-roundtrip",
    FIXTURES / "phase4-player-form-swapteam",
    FIXTURES / "phase5-two-player-readonly",
    FIXTURES / "phase5-chat-live-cursors",
    FIXTURES / "phase5-webadmin-chat-send",
    FIXTURES / "phase5-player-form-swapteam",
    FIXTURES / "phase5-player-form-whisper",
    FIXTURES / "phase5-two-player-kick",
    FIXTURES / "phase5-post-kick-reconnect",
    FIXTURES / "phase5-two-player-session-ban",
    FIXTURES / "phase5-post-session-ban-reconnect",
    FIXTURES / "phase5-two-player-permanent-ban",
    FIXTURES / "phase5-post-permanent-ban-reconnect",
    FIXTURES / "phase5-two-player-role-kick",
    FIXTURES / "phase5-two-player-role-kick-commander",
    FIXTURES / "phase5-post-role-kick",
    FIXTURES / "phase5-stale-player-key",
    FIXTURES / "phase5-post-reciprocal-kills",
    FIXTURES / "phase5-toxic-players-after-teamkills",
    FIXTURES / "phase5-squad-reset",
    FIXTURES / "phase5-post-squad-reset-restore",
    FIXTURES / "phase5-squad-data-route",
    FIXTURES / "phase5-team-kill-baseline",
    FIXTURES / "phase5-one-team-kill-after",
)
REQUIRED_FILES = (
    ROOT / "README.md",
    ROOT / "protocol.md",
    ROOT / "api-reference.md",
    ROOT / "bundled-client-assets.md",
    ROOT / "MOCK_IMPLEMENTER_GUIDE.md",
    ROOT / "SOURCE_DATA_SETUP.md",
    ROOT / "source-data.example.toml",
    ROOT / "EXPERIMENTAL_DISCOVERY_RUNBOOK.md",
    ROOT / "rs2wapy-coverage.md",
    ROOT / "contract.yaml",
    ROOT / "tools" / "probe_webadmin.py",
    ROOT / "tools" / "player_action_probe.py",
    ROOT / "tools" / "banid_roundtrip_probe.py",
    ROOT / "tools" / "kick_ban_probe.py",
    ROOT / "tools" / "multiadmin_probe.py",
    ROOT / "tools" / "readonly_profile_probe.py",
    ROOT / "tools" / "multiadmin_permission_probe.py",
    ROOT / "tools" / "empty_state_probe.py",
    ROOT / "tools" / "phase3_core_probe.py",
    ROOT / "tools" / "travel_roundtrip_probe.py",
    ROOT / "tools" / "policy_validation_probe.py",
    ROOT / "tools" / "welcome_settings_probe.py",
    ROOT / "tools" / "console_log_probe.py",
    ROOT / "tools" / "player_form_fallback_probe.py",
    ROOT / "tools" / "player_form_membership_probe.py",
    ROOT / "tools" / "tracking_alias_roundtrip_probe.py",
    ROOT / "tools" / "tracking_note_roundtrip_probe.py",
    ROOT / "tools" / "player_form_swapteam_probe.py",
    ROOT / "tools" / "player_form_whisper_probe.py",
    ROOT / "tools" / "two_player_kick_probe.py",
    ROOT / "tools" / "two_player_session_ban_probe.py",
    ROOT / "tools" / "admin_target_sessionban_probe.py",
    ROOT / "tools" / "two_player_permanent_ban_probe.py",
    ROOT / "tools" / "two_player_role_kick_probe.py",
    ROOT / "tools" / "stale_player_key_probe.py",
    ROOT / "tools" / "toxic_players_readonly_probe.py",
    ROOT / "tools" / "squad_reset_probe.py",
    ROOT / "tools" / "squad_data_route_probe.py",
    ROOT / "tools" / "two_player_readonly_probe.py",
    ROOT / "tools" / "two_session_chat_wait_probe.py",
)
FORBIDDEN_PATTERNS = {
    "session-cookie": re.compile(r'sessionid="?[a-f0-9]{16,}', re.IGNORECASE),
    "auth-cookie": re.compile(r'authcred="?(?!\{\{)[^;\s"]+', re.IGNORECASE),
    "ipv4-address": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "steam-or-hex-id": re.compile(r"\b(?:0x[0-9a-f]{8,}|\d{15,20})\b", re.IGNORECASE),
    "player-key": re.compile(r"\b\d+_0x[0-9a-f]+_[\d.]+\b", re.IGNORECASE),
}
PLAYER_TABLE_PATTERN = re.compile(
    r'<table\b[^>]*\bid=["\']players["\'][^>]*>(.*?)</table>',
    re.IGNORECASE | re.DOTALL,
)
PLAYER_ROW_NAME_PATTERN = re.compile(
    r"<tr\b[^>]*>\s*<td\b[^>]*>.*?</td>\s*<td\b[^>]*>([^<]*?)</td>",
    re.IGNORECASE | re.DOTALL,
)
ADMIN_OPTION_PATTERN = re.compile(
    r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\bclass=["\']admin(?:Enabled|Disabled)["\'][^>]*>([^<]*)</option>',
    re.IGNORECASE,
)
ADMIN_DISPLAY_PATTERN = re.compile(
    r'<input\b[^>]*\bname=["\']displayname["\'][^>]*\bvalue=["\']([^"\']*)',
    re.IGNORECASE,
)


def capture_names(directory: Path) -> set[str]:
    index_path = directory / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    failures = index.get("failures", [])
    if failures:
        raise ValueError(f"capture failures in {directory.name}: {failures}")
    names = {
        reference
        for entry in index["captures"]
        for reference in (entry["name"], Path(entry["response"]).stem)
    }
    for entry in index["captures"]:
        for key in ("request", "response"):
            if not (directory / entry[key]).is_file():
                raise ValueError(f"missing {key} fixture for {entry['name']}")
    return names


def validate_sanitization(directory: Path) -> None:
    for path in directory.iterdir():
        if not path.is_file():
            continue
        contents = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(contents):
                raise ValueError(f"{label} found in {path.relative_to(ROOT)}")
        player_values = re.findall(
            r'name=["\']__PlayerName_\d+["\'][^>]*value=["\']([^"\']*)',
            contents,
            re.IGNORECASE,
        )
        if any(
            value and not re.fullmatch(r"\{\{PLAYER_\d+\}\}", value)
            for value in player_values
        ):
            raise ValueError(f"raw player name found in {path.relative_to(ROOT)}")
        for table in PLAYER_TABLE_PATTERN.finditer(contents):
            for player_name in PLAYER_ROW_NAME_PATTERN.findall(table.group(1)):
                if player_name.strip() and not re.fullmatch(
                    r"\{\{PLAYER_\d+\}\}", player_name.strip()
                ):
                    raise ValueError(
                        f"raw player table name found in {path.relative_to(ROOT)}"
                    )
        for value, text in ADMIN_OPTION_PATTERN.findall(contents):
            if value and not re.fullmatch(r"\{\{ADMIN_\d+\}\}", value):
                raise ValueError(
                    f"raw administrator ID found in {path.relative_to(ROOT)}"
                )
            if text.strip() and not re.fullmatch(r"\{\{ADMIN_\d+\}\}", text.strip()):
                raise ValueError(
                    f"raw administrator name found in {path.relative_to(ROOT)}"
                )
        for value in ADMIN_DISPLAY_PATTERN.findall(contents):
            if value and not re.fullmatch(r"\{\{ADMIN_DISPLAY_\d+\}\}", value):
                raise ValueError(
                    f"raw administrator display name found in {path.relative_to(ROOT)}"
                )


def contract_fixture_names(contract: str) -> set[str]:
    names = set(re.findall(r"^\s+fixture:\s+([\w-]+)\s*$", contract, re.MULTILINE))
    for match in re.findall(r"^\s+fixtures:\s+\[([^]]+)\]\s*$", contract, re.MULTILINE):
        names.update(value.strip() for value in match.split(","))
    return names


def run() -> int:
    missing = [
        str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.is_file()
    ]
    if missing:
        logger.warning("missing required files: {}", ", ".join(missing))
        return 1
    try:
        names_by_directory = {
            directory.name: capture_names(directory) for directory in CAPTURE_DIRS
        }
        for directory in CAPTURE_DIRS:
            validate_sanitization(directory)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        logger.error("documentation validation error: {}", error)
        return 1

    contract = (ROOT / "contract.yaml").read_text(encoding="utf-8")
    if "contract_version: 1" not in contract or "endpoints:" not in contract:
        logger.warning("contract does not declare version 1 endpoints")
        return 1
    documented_fixtures = contract_fixture_names(contract)
    captured_names = set().union(*names_by_directory.values())
    missing_fixtures = sorted(documented_fixtures - captured_names)
    if missing_fixtures:
        logger.warning("contract refers to missing captures: {}", ", ".join(missing_fixtures))
        return 1
    if {"chat-post", "chat-data-after-post"} - captured_names:
        logger.warning("chat write evidence is missing")
        return 1
    if {"policy-add", "policy-delete", "policy-after-delete"} - captured_names:
        logger.warning("policy roundtrip evidence is missing")
        return 1
    if {
        "player-mutevoice",
        "player-unmutevoice",
        "player-sessionban",
        "session-bans-after-revoke",
        "player-banid",
        "permanent-bans-after-revoke",
        "player-kick",
        "player-banid-permanent",
        "kick-ban-permanent-bans-after-action",
        "logout-kick-ban-actions",
    } - captured_names:
        logger.warning("player-action evidence is missing")
        return 1
    logger.info(
        "validated {} capture names across {} fixture sets",
        len(captured_names),
        len(CAPTURE_DIRS),
    )
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
def main() -> None:
    """Validate the RS2 WebAdmin documentation capture set."""
    configure_logging()
    exit_with_status(run())


if __name__ == "__main__":
    main()
