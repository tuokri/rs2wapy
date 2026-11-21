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
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Seed and verify synthetic tracking/member/ban pagination records."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import click
import httpx2
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture
from udk_configparser import UDKConfigParser  # type: ignore[import-untyped]

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS  # type: ignore[import-untyped]
from webadmin_api_docs.logging import configure_logging  # type: ignore[import-untyped]
from webadmin_api_docs.logging import logger  # type: ignore[import-untyped]

DEFAULT_TRACK_DB = Path(r"O:\rs2server\ROGame\Config\ROTrackDb.ini")
DEFAULT_MEMBER_DB = Path(r"O:\rs2server\ROGame\Config\ROMemberDb.ini")
DEFAULT_GAME_INI = Path(r"O:\rs2server\ROGame\Config\ROGame.ini")
DEFAULT_BACKUP_DIR = Path.home() / ".rs2wapy" / "synthetic-pagination-backups"
SERVER_EXECUTABLE = Path(r"O:\rs2server\Binaries\Win64\VNGame.exe")
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERIFY_OUTPUT = ROOT / "fixtures" / "phase7-pagination-synthetic-live-20261121"

TRACK_DUMMY_PLAYER = '(PlayerID="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",NetId=(Uid=(A=0,B=0)),SteamId64="0x0",PlayerNames=("xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE"),Created="12/14/1980 0:00:01",LastSeen="12/14/1980 0:00:01",alias=(Who=(Name=,NetId=(Uid=(A=0,B=0))),Created=,alias=),NoteIds=,PunkIds=("xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE"),NrOf=(Kicks=0,SessionBans=0,Bans=0,Connects=0),Track=False)'
TRACK_DUMMY_PUNK = '(PunkId="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",PlayerID="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Admin=(Name=,NetId=(Uid=(A=0,B=0))),Created="12/14/1980 0:00:01",Closed=,PunkName="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Reason="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Expires=,Type=PunkType_None,Status=PunkStatus_None,Offline=True)'
MEMBER_DUMMY = '(MemberId="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",NetId=(Uid=(A=0,B=0)),SteamId64="0x0",MemberName="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",alias=,AdminConfig=,Created="12/14/1980 0:00:01",LastSeen="12/14/1980 0:00:01",Expires=,Status=SubscriptionStatus_Cancelled,Closed=)'
BANNED_DUMMY = "(Uid=(A=0,B=0))"

SYNTHETIC_BAN_MIN = 40_000_001
SYNTHETIC_BAN_MAX = 40_999_999
MAX_SYNTHETIC_ROWS = 10_000
PAGINATION_ACTIONS = ("firstpage", "previouspage", "nextpage", "lastpage")


@dataclass(frozen=True, slots=True)
class ChangeState:
    game_type: str
    map_name: str
    mutator_group_count: str
    mutators: dict[str, str]
    url_extra: str
    maps: tuple[str, ...]


def backup_config_files(
    backup_dir: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Back up live config files without replacing an existing baseline."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    backups: dict[str, Path] = {}
    for name, source in (
        ("track", DEFAULT_TRACK_DB),
        ("members", DEFAULT_MEMBER_DB),
        ("game", DEFAULT_GAME_INI),
    ):
        if not source.is_file():
            raise RuntimeError(f"missing config file: {source}")
        destination = backup_dir / source.name
        if destination.exists() and not overwrite:
            logger.info("preserving existing baseline backup '{}'", destination)
        else:
            shutil.copy2(source, destination)
            logger.info("backed up '{}' to '{}'", source, destination)
        backups[name] = destination
    return backups


def restore_config_files(backups: dict[str, Path]) -> None:
    """Restore live config files from a backup mapping."""
    destinations = (
        ("track", DEFAULT_TRACK_DB),
        ("members", DEFAULT_MEMBER_DB),
        ("game", DEFAULT_GAME_INI),
    )
    for name, destination in destinations:
        backup = backups.get(name)
        if backup is None or not backup.is_file():
            raise RuntimeError(f"missing {name} config backup")
        shutil.copy2(backup, destination)
        logger.info("restored '{}' from '{}'", destination, backup)


def backup_mapping_for_dir(backup_dir: Path) -> dict[str, Path]:
    """Resolve the expected source-name backups inside a directory."""
    return {
        "track": backup_dir / DEFAULT_TRACK_DB.name,
        "members": backup_dir / DEFAULT_MEMBER_DB.name,
        "game": backup_dir / DEFAULT_GAME_INI.name,
    }


def remove_synthetic_table_entries(values: list[str], marker: str) -> list[str]:
    """Remove prior synthetic and dummy entries while preserving real rows."""
    return [
        value
        for value in values
        if marker not in value
        and "xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE" not in value
    ]


def remove_synthetic_bans(values: list[str]) -> list[str]:
    """Remove prior synthetic banned UIDs and the BannedIDs dummy entry."""
    retained: list[str] = []
    for value in values:
        if "xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE" in value:
            continue
        if "(Uid=(A=0,B=0))" in value:
            continue
        match = re.search(r"Uid=\(A=(\d+),B=17825793\)", value)
        if match:
            uid_a = int(match.group(1))
            if SYNTHETIC_BAN_MIN <= uid_a <= SYNTHETIC_BAN_MAX:
                continue
        retained.append(value)
    return retained


def synthetic_tracking_rows(count: int) -> tuple[list[str], list[str], list[str]]:
    """Build synthetic player, punk, and permanent banned-ID values."""
    players: list[str] = []
    punks: list[str] = []
    banned_ids: list[str] = []

    for index in range(1, count + 1):
        number = f"{index:03d}"
        player_id = f"0x{0x7000000000000000 + index:016X}"
        net_id_a = 20_000_000 + index
        steam_id = f"7656119900000{index:05d}"
        punk_id = f"synthetic-punk-{number}"
        player = (
            f'(PlayerID="{player_id}",NetId=(Uid=(A={net_id_a},B=17825793)),'
            f'SteamId64="{steam_id}",PlayerNames=("synthetic-tracking-{number}"),'
            'Created="2026/11/21 - 12:50:00",'
            'LastSeen="2026/11/21 - 12:50:00",'
            'alias=(Who=(Name=,NetId=(Uid=(A=0,B=0))),Created=,alias=),'
            f'NoteIds=,PunkIds=("{punk_id}"),'
            'NrOf=(Kicks=0,SessionBans=0,Bans=1,Connects=0),Track=False)'
        )
        punk = (
            f'(PunkId="{punk_id}",PlayerID="{player_id}",'
            'Admin=(Name="Synthetic",NetId=(Uid=(A=0,B=0))),'
            'Created="2026/11/21 - 12:50:00",Closed=,'
            f'PunkName="synthetic-tracking-{number}",'
            'Reason="Synthetic pagination ban",Expires=,'
            'Type=PunkType_Ban,Status=PunkStatus_Active,Offline=True)'
        )
        players.append(player)
        punks.append(punk)
        banned_ids.append(
            f"(Uid=(A={SYNTHETIC_BAN_MIN + index - 1},B=17825793))"
        )

    return players, punks, banned_ids


def synthetic_member_rows(count: int) -> list[str]:
    """Build synthetic member-table values."""
    members: list[str] = []
    for index in range(1, count + 1):
        number = f"{index:03d}"
        member_id = f"0x{0x7100000000000000 + index:016X}"
        net_id_a = 30_000_000 + index
        steam_id = f"7656119900010{index:05d}"
        members.append(
            f'(MemberId="{member_id}",NetId=(Uid=(A={net_id_a},B=17825793)),'
            f'SteamId64="{steam_id}",MemberName="synthetic-member-{number}",'
            'alias=,AdminConfig=,Created="2026/11/21 - 12:50:00",'
            'LastSeen="2026/11/21 - 12:50:00",Expires=,'
            'Status=SubscriptionStatus_Active,Closed=)'
        )
    return members


def write_parser(
    parser: UDKConfigParser,
    destination: Path,
) -> None:
    """Write and flush one UDK config temp copy."""
    with destination.open("w", encoding="utf-8") as output:
        parser.write(output, space_around_delimiters=False)


def prepare_synthetic_temp_files(
    count: int,
    temp_dir: Path,
    track_source: Path = DEFAULT_TRACK_DB,
    member_source: Path = DEFAULT_MEMBER_DB,
    game_source: Path = DEFAULT_GAME_INI,
) -> dict[str, Path]:
    """Copy live configs to temp files and validate every synthetic write."""
    temp_dir.mkdir(parents=True, exist_ok=True)
    tracking_temp = temp_dir / track_source.name
    member_temp = temp_dir / member_source.name
    game_temp = temp_dir / game_source.name
    shutil.copy2(track_source, tracking_temp)
    shutil.copy2(member_source, member_temp)
    shutil.copy2(game_source, game_temp)

    players, punks, banned_ids = synthetic_tracking_rows(count)
    members = synthetic_member_rows(count)

    tracking_parser = UDKConfigParser(strict=False)
    tracking_parser.read(str(tracking_temp))
    existing_players = tracking_parser["ROGame.TrackDb"].getlist("Table_Players")
    real_players = remove_synthetic_table_entries(
        existing_players,
        "synthetic-tracking",
    )
    tracking_parser["ROGame.TrackDb"]["Table_Players"] = "\n".join(
        real_players + players + [TRACK_DUMMY_PLAYER]
    )

    existing_punks = tracking_parser["ROGame.TrackDb"].getlist("Table_Punks")
    real_punks = remove_synthetic_table_entries(existing_punks, "synthetic-punk")
    tracking_parser["ROGame.TrackDb"]["Table_Punks"] = "\n".join(
        real_punks + punks + [TRACK_DUMMY_PUNK]
    )
    write_parser(tracking_parser, tracking_temp)

    tracking_validation = UDKConfigParser(strict=False)
    tracking_validation.read(str(tracking_temp))
    written_players = tracking_validation["ROGame.TrackDb"].getlist("Table_Players")
    written_punks = tracking_validation["ROGame.TrackDb"].getlist("Table_Punks")
    if count_marker(written_players, "synthetic-tracking") != count:
        raise RuntimeError("synthetic parser did not write Table_Players correctly")
    if count_marker(written_punks, "synthetic-punk") != count:
        raise RuntimeError("synthetic parser did not write Table_Punks correctly")

    member_parser = UDKConfigParser(strict=False)
    member_parser.read(str(member_temp))
    existing_members = member_parser["ROGame.MemberDb"].getlist("Table_Members")
    real_members = remove_synthetic_table_entries(
        existing_members,
        "synthetic-member",
    )
    member_parser["ROGame.MemberDb"]["Table_Members"] = "\n".join(
        real_members + members + [MEMBER_DUMMY]
    )
    write_parser(member_parser, member_temp)

    member_validation = UDKConfigParser(strict=False)
    member_validation.read(str(member_temp))
    written_members = member_validation["ROGame.MemberDb"].getlist("Table_Members")
    if count_marker(written_members, "synthetic-member") != count:
        raise RuntimeError("synthetic parser did not write Table_Members correctly")

    game_parser = UDKConfigParser(strict=False)
    game_parser.read(str(game_temp))
    existing_bans = game_parser["Engine.AccessControl"].getlist("BannedIDs")
    real_bans = remove_synthetic_bans(existing_bans)
    game_parser["Engine.AccessControl"]["BannedIDs"] = "\n".join(
        real_bans + banned_ids + [BANNED_DUMMY]
    )
    write_parser(game_parser, game_temp)

    game_validation = UDKConfigParser(strict=False)
    game_validation.read(str(game_temp))
    written_bans = game_validation["Engine.AccessControl"].getlist("BannedIDs")
    if count_synthetic_bans(written_bans) != count:
        raise RuntimeError("synthetic parser did not write BannedIDs correctly")

    return {
        "track": tracking_temp,
        "members": member_temp,
        "game": game_temp,
    }


def count_marker(values: list[str], marker: str) -> int:
    """Count values carrying one synthetic marker."""
    return sum(marker in value for value in values)


def count_synthetic_bans(values: list[str]) -> int:
    """Count banned UIDs in the disposable synthetic UID range."""
    count = 0
    for value in values:
        match = re.search(r"Uid=\(A=(\d+),B=17825793\)", value)
        if match:
            uid_a = int(match.group(1))
            if SYNTHETIC_BAN_MIN <= uid_a <= SYNTHETIC_BAN_MAX:
                count += 1
    return count


def count_synthetic_bans_in_html(body: str) -> int:
    """Count synthetic permanent-ban rows rendered in one WebAdmin page."""
    return body.count("Synthetic pagination ban")


def extract_hidden_index(body: str, field_name: str) -> int | None:
    """Extract an integer hidden pagination index from route HTML."""
    match = re.search(
        rf'name="{re.escape(field_name)}"[^>]*value="([^"]*)"',
        body,
        re.IGNORECASE,
    )
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def count_route_row_fields(body: str, route: str) -> int:
    """Count unique rendered row-field identifiers for one policy route."""
    field_name = {
        "policy/tracking": "__PlayerName",
        "policy/members": "__MemberName",
        "policy/bans": "__UniqueId",
    }[route]
    return len(
        set(
            re.findall(
                rf'name="{re.escape(field_name)}_(\d+)"',
                body,
                re.IGNORECASE,
            )
        )
    )


def count_synthetic_route_markers(body: str, route: str) -> int:
    """Count synthetic markers visible on one policy route page."""
    if route == "policy/tracking":
        return len(set(re.findall(r"synthetic-tracking-(\d+)", body)))
    if route == "policy/members":
        return len(set(re.findall(r"synthetic-member-(\d+)", body)))
    if route == "policy/bans":
        return count_synthetic_bans_in_html(body)
    return 0


def build_page_boundary_summary(captures: list[Capture]) -> dict[str, object]:
    """Summarize row counts and hidden indexes for pagination actions."""
    boundary_summary: dict[str, object] = {}
    for route in ("policy/tracking", "policy/members", "policy/bans"):
        route_name = route.replace("/", "-")
        actions: dict[str, object] = {}
        for action in ("baseline", *PAGINATION_ACTIONS, "tab0", "tab1"):
            capture = next(
                (
                    item
                    for item in captures
                    if item.name == f"{route_name}-{action}"
                ),
                None,
            )
            if capture is None:
                continue
            actions[action] = {
                "row_fields": count_route_row_fields(capture.body, route),
                "synthetic_markers": count_synthetic_route_markers(
                    capture.body,
                    route,
                ),
                "first_visible_row_index": extract_hidden_index(
                    capture.body,
                    "__FirstVisibleRowIndex",
                ),
                "current_tab_index": extract_hidden_index(
                    capture.body,
                    "__CurrentTabIndex",
                ),
            }
        boundary_summary[route] = actions
    return boundary_summary


def extract_page_row_keys(body: str, route: str) -> list[str]:
    """Extract rendered row-key identifiers for stale/duplicate-page checks."""
    field_name = {
        "policy/tracking": "__PlayerName",
        "policy/members": "__MemberName",
        "policy/bans": "__UniqueId",
    }[route]
    return re.findall(
        rf'name="{re.escape(field_name)}_(\d+)"',
        body,
        re.IGNORECASE,
    )


def build_page_sequence_summary(captures: list[Capture]) -> dict[str, object]:
    """Summarize an ordered first/next/previous/last page sequence."""
    sequence_summary: dict[str, object] = {}
    for route in ("policy/tracking", "policy/members", "policy/bans"):
        route_name = route.replace("/", "-")
        pages: dict[str, object] = {}
        duplicate_keys: dict[str, list[str]] = {}
        for action in (
            "baseline",
            "sequence-first",
            "sequence-next-1",
            "sequence-next-2",
            "sequence-prev",
            "sequence-last",
            "sequence-prev-after-last",
        ):
            capture = next(
                (
                    item
                    for item in captures
                    if item.name == f"{route_name}-{action}"
                ),
                None,
            )
            if capture is None:
                continue
            keys = extract_page_row_keys(capture.body, route)
            pages[action] = {
                "row_fields": len(keys),
                "unique_row_fields": len(set(keys)),
                "synthetic_markers": count_synthetic_route_markers(
                    capture.body,
                    route,
                ),
                "first_visible_row_index": extract_hidden_index(
                    capture.body,
                    "__FirstVisibleRowIndex",
                ),
                "current_tab_index": extract_hidden_index(
                    capture.body,
                    "__CurrentTabIndex",
                ),
            }
            key_counts: dict[str, int] = {}
            for key in keys:
                key_counts[key] = key_counts.get(key, 0) + 1
            repeated_on_page = sorted(
                key
                for key, count in key_counts.items()
                if count > 1
            )
            if repeated_on_page:
                duplicate_keys[action] = repeated_on_page

        repeated_across_pages: dict[str, list[str]] = {}
        all_seen: set[str] = set()
        for action in pages:
            capture = next(
                (
                    item
                    for item in captures
                    if item.name == f"{route_name}-{action}"
                ),
                None,
            )
            if capture is None:
                continue
            key_set = set(extract_page_row_keys(capture.body, route))
            repeated_across_pages[action] = sorted(key_set & all_seen)
            all_seen |= key_set

        sequence_summary[route] = {
            "pages": pages,
            "repeated_across_pages": repeated_across_pages,
            "duplicate_keys_on_page": duplicate_keys,
        }
    return sequence_summary


def inspect_synthetic_configs(
    track_path: Path,
    member_path: Path,
    game_path: Path,
) -> dict[str, int]:
    """Return exact synthetic row counts in three config copies."""
    tracking = UDKConfigParser(strict=False)
    tracking.read(str(track_path))
    players = tracking["ROGame.TrackDb"].getlist("Table_Players")
    punks = tracking["ROGame.TrackDb"].getlist("Table_Punks")

    members = UDKConfigParser(strict=False)
    members.read(str(member_path))
    member_values = members["ROGame.MemberDb"].getlist("Table_Members")

    game = UDKConfigParser(strict=False)
    game.read(str(game_path))
    ban_values = game["Engine.AccessControl"].getlist("BannedIDs")

    return {
        "tracking_players": count_marker(players, "synthetic-tracking"),
        "tracking_punks": count_marker(punks, "synthetic-punk"),
        "members": count_marker(member_values, "synthetic-member"),
        "bans": count_synthetic_bans(ban_values),
    }


def validate_synthetic_configs(
    count: int,
    temp_dir: Path,
) -> dict[str, int]:
    """Validate synthetic writes on temp copies without touching live configs."""
    temp_files = prepare_synthetic_temp_files(count, temp_dir)
    stats = inspect_synthetic_configs(
        temp_files["track"],
        temp_files["members"],
        temp_files["game"],
    )
    if any(value != count for value in stats.values()):
        raise RuntimeError(f"temp synthetic validation mismatch: {stats}")
    return stats


def seed_synthetic_configs(
    count: int,
    backup_dir: Path,
) -> tuple[dict[str, Path], dict[str, int]]:
    """Back up, temp-validate, and seed all live synthetic config data."""
    backups = backup_config_files(backup_dir)
    with tempfile.TemporaryDirectory(prefix="rs2-synthetic-pagination-") as temp:
        temp_files = prepare_synthetic_temp_files(count, Path(temp))
        stats = inspect_synthetic_configs(
            temp_files["track"],
            temp_files["members"],
            temp_files["game"],
        )
        if any(value != count for value in stats.values()):
            raise RuntimeError(f"temp synthetic validation mismatch: {stats}")
        shutil.copy2(temp_files["track"], DEFAULT_TRACK_DB)
        shutil.copy2(temp_files["members"], DEFAULT_MEMBER_DB)
        shutil.copy2(temp_files["game"], DEFAULT_GAME_INI)

    live_stats = inspect_synthetic_configs(
        DEFAULT_TRACK_DB,
        DEFAULT_MEMBER_DB,
        DEFAULT_GAME_INI,
    )
    if live_stats != stats:
        raise RuntimeError(
            f"live synthetic config mismatch: temp={stats}, live={live_stats}"
        )
    return backups, live_stats


def find_live_vngame_pids() -> list[int]:
    """Find running VNGame instances by their known executable path."""
    escaped = str(SERVER_EXECUTABLE).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        "Get-CimInstance Win32_Process -Filter \"Name='VNGame.exe'\" "
        "| Where-Object { $_.ExecutablePath -eq '" + escaped + "' } "
        "| Select-Object -ExpandProperty ProcessId"
    )
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        int(line)
        for line in result.stdout.splitlines()
        if line.strip().isdigit()
    ]


def ensure_server_stopped_for_seed() -> None:
    """Refuse direct live writes while VNGame owns the config databases."""
    pids = find_live_vngame_pids()
    if pids:
        raise RuntimeError(
            "VNGame is running (PID "
            + ",".join(str(pid) for pid in pids)
            + "); stop/restart with --restart instead of direct seeding"
        )


def stop_vngame(pids: list[int]) -> None:
    """Stop only the known VNGame PIDs."""
    for pid in pids:
        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Stop-Process -Id {pid} -Force",
            ],
            check=True,
        )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not find_live_vngame_pids():
            return
        time.sleep(1)
    raise RuntimeError("VNGame did not stop within 30 seconds")


def restart_and_seed_synthetic_configs(
    count: int,
    backup_dir: Path,
    server_map: str,
) -> tuple[dict[str, Path], dict[str, int], int]:
    """Stop VNGame, seed temp-validated configs, and restart it."""
    pids = find_live_vngame_pids()
    if len(pids) != 1:
        raise RuntimeError(
            f"expected exactly one live VNGame server, found {len(pids)}"
        )
    stop_vngame(pids)
    try:
        backups, stats = seed_synthetic_configs(count, backup_dir)
    except (OSError, RuntimeError) as error:
        try:
            restore_config_files(backup_mapping_for_dir(backup_dir))
        except (OSError, RuntimeError) as restore_error:
            raise RuntimeError(
                f"synthetic seed failed: {error}; restore also failed: {restore_error}"
            ) from restore_error
        subprocess.Popen(
            [
                str(SERVER_EXECUTABLE),
                server_map,
                "-log",
                "-FORCELOGFLUSH",
            ],
            cwd=str(SERVER_EXECUTABLE.parent),
        )
        raise RuntimeError(f"synthetic seed failed while VNGame was stopped: {error}")
    process = subprocess.Popen(
        [
            str(SERVER_EXECUTABLE),
            server_map,
            "-log",
            "-FORCELOGFLUSH",
        ],
        cwd=str(SERVER_EXECUTABLE.parent),
    )
    return backups, stats, process.pid


def validate_baseline_backups(backup_dir: Path) -> dict[str, Path]:
    """Require exact pre-synthetic backup files before a boundary run."""
    backups = backup_mapping_for_dir(backup_dir)
    for name, path in backups.items():
        if not path.is_file():
            raise RuntimeError(f"missing baseline {name} backup: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        has_synthetic_marker = bool(
            re.search(
                r"synthetic-tracking|synthetic-punk|synthetic-member",
                content,
                re.IGNORECASE,
            )
        )
        has_synthetic_ban = bool(
            re.search(
                r"A=40\d{5},B=17825793",
                content,
                re.IGNORECASE,
            )
        )
        if has_synthetic_marker or has_synthetic_ban:
            raise RuntimeError(
                f"baseline {name} backup contains synthetic data: {path}"
            )
    return backups


def wait_for_webadmin(base_url: str, wait_seconds: int) -> None:
    """Wait until WebAdmin answers on the expected listener."""
    normalized = base_url.rstrip("/") + "/"
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            response = httpx2.get(normalized, timeout=5)
            if response.status_code == 200:
                return
        except httpx2.RequestError:
            pass
        time.sleep(1)
    raise RuntimeError(
        f"WebAdmin did not become ready within {wait_seconds} seconds"
    )


def restore_and_restart_baseline(
    backup_dir: Path,
    server_map: str,
) -> int:
    """Restore exact baseline configs and restart the known VNGame server."""
    pids = find_live_vngame_pids()
    if pids:
        stop_vngame(pids)
    backups = validate_baseline_backups(backup_dir)
    restore_config_files(backups)
    process = subprocess.Popen(
        [
            str(SERVER_EXECUTABLE),
            server_map,
            "-log",
            "-FORCELOGFLUSH",
        ],
        cwd=str(SERVER_EXECUTABLE.parent),
    )
    return process.pid


def selected_value(body: str, select_id: str) -> tuple[str, tuple[str, ...]]:
    """Read one selected value and all options from a change-page select."""
    select_match = re.search(
        rf'<select[^>]*\bid=["\']{re.escape(select_id)}["\'][^>]*>(.*?)</select>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not select_match:
        raise RuntimeError(f"change page did not contain {select_id} select")
    options = re.findall(
        r'<option[^>]*\bvalue=["\']([^"\']+)["\']([^>]*)>',
        select_match.group(1),
        re.IGNORECASE,
    )
    selected = [
        value
        for value, attributes in options
        if "selected" in attributes.lower()
    ]
    if len(selected) != 1:
        raise RuntimeError(
            f"change page did not contain one selected {select_id} value"
        )
    return selected[0], tuple(value for value, _ in options)


def parse_change_state(body: str) -> ChangeState:
    """Parse the live change-map form state."""
    game_type, _ = selected_value(body, "gametype")
    map_name, maps = selected_value(body, "map")
    group_match = re.search(
        r'<input[^>]*\bname=["\']mutatorGroupCount["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    extra_match = re.search(
        r'<input[^>]*\bid=["\']urlextra["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    if not group_match or not extra_match:
        raise RuntimeError("change page did not contain mutator or URL-extra fields")
    mutators = {
        name: value
        for name, value, attributes in re.findall(
            r'<input[^>]*\bname=["\'](mutgroup\d+)["\'][^>]*\bvalue=["\']([^"\']*)["\']([^>]*)>',
            body,
            re.IGNORECASE,
        )
        if "checked" in attributes.lower()
    }
    return ChangeState(
        game_type=game_type,
        map_name=map_name,
        mutator_group_count=group_match.group(1),
        mutators=mutators,
        url_extra=extra_match.group(1),
        maps=maps,
    )


def change_level(
    base_url: str,
    username: str,
    password: str,
    target_map: str | None,
    wait_seconds: int,
) -> str:
    """Travel to an alternate live map to trigger a config reload."""
    probe = WebAdminProbe(base_url, username, password)
    probe.login()
    baseline = probe.request("synthetic-change-baseline", "current/change")
    state = parse_change_state(baseline.body)
    destination = target_map
    if destination is None:
        destination = next(
            (map_name for map_name in state.maps if map_name != state.map_name),
            None,
        )
    if destination is None:
        raise RuntimeError("no alternate map was available for a level change")
    if destination not in state.maps:
        raise RuntimeError(f"target map '{destination}' was not in the change page")

    form = {
        "action": "change",
        "gametype": state.game_type,
        "map": destination,
        "mutatorGroupCount": state.mutator_group_count,
        "urlextra": state.url_extra,
        **state.mutators,
    }
    probe.request("synthetic-level-change", "current/change", form)

    deadline = time.monotonic() + wait_seconds
    attempt = 0
    while True:
        attempt += 1
        check = probe.request(
            f"synthetic-level-change-check-{attempt}",
            "current/change/check",
        )
        if check.status == 200 and check.body.strip().lower() == "ok":
            return destination
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"level change did not become ready within {wait_seconds} seconds"
            )
        time.sleep(1)


def login_credentials(
    username: str | None,
    password: str | None,
) -> tuple[str, str]:
    """Resolve credentials from options/env or the local live server config."""
    resolved_username = username or os.environ.get("RS2_WEBADMIN_USERNAME") or "Admin"
    resolved_password = password or os.environ.get("RS2_WEBADMIN_PASSWORD")
    if not resolved_password:
        parser = UDKConfigParser(strict=False)
        parser.read(str(DEFAULT_GAME_INI))
        resolved_password = parser["Engine.AccessControl"]["AdminPassword"]
    if not resolved_password:
        raise RuntimeError("WebAdmin password was not configured")
    return resolved_username, resolved_password


def verify_live_routes(
    base_url: str,
    username: str,
    password: str,
    output: Path,
) -> dict[str, object]:
    """Capture and verify synthetic tracking/member/ban route data."""
    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    tracking_names: set[str] = set()
    member_names: set[str] = set()
    ban_uid_a: set[str] = set()
    ban_reason_count = 0
    probe: WebAdminProbe | None = None

    try:
        probe = WebAdminProbe(base_url, username, password)
        captures.extend(probe.login())
        for route in ("policy/tracking", "policy/members", "policy/bans"):
            route_name = route.replace("/", "-")
            captures.append(probe.request(f"{route_name}-baseline", route))
            for action in PAGINATION_ACTIONS:
                captures.append(
                    probe.request(
                        f"{route_name}-{action}",
                        route,
                        {
                            "action": action,
                            "__CurrentTabIndex": "0",
                            "__FirstVisibleRowIndex": "0",
                        },
                    )
                )
            if route in ("policy/tracking", "policy/members"):
                captures.append(
                    probe.request(
                        f"{route_name}-tab1",
                        route,
                        {
                            "action": "",
                            "__CurrentTabIndex": "1",
                            "__FirstVisibleRowIndex": "0",
                        },
                    )
                )
                captures.append(
                    probe.request(
                        f"{route_name}-tab0",
                        route,
                        {
                            "action": "",
                            "__CurrentTabIndex": "0",
                            "__FirstVisibleRowIndex": "0",
                        },
                    )
                )
            current_index = "0"
            current_tab = "0"
            sequence_actions = (
                ("sequence-first", "firstpage"),
                ("sequence-next-1", "nextpage"),
                ("sequence-next-2", "nextpage"),
                ("sequence-prev", "previouspage"),
                ("sequence-last", "lastpage"),
                ("sequence-prev-after-last", "previouspage"),
            )
            for capture_name, action in sequence_actions:
                capture = probe.request(
                    f"{route_name}-{capture_name}",
                    route,
                    {
                        "action": action,
                        "__CurrentTabIndex": current_tab,
                        "__FirstVisibleRowIndex": current_index,
                    },
                )
                captures.append(capture)
                returned_index = extract_hidden_index(
                    capture.body,
                    "__FirstVisibleRowIndex",
                )
                returned_tab = extract_hidden_index(
                    capture.body,
                    "__CurrentTabIndex",
                )
                if returned_index is not None:
                    current_index = str(returned_index)
                if returned_tab is not None:
                    current_tab = str(returned_tab)
        for capture in captures:
            tracking_names.update(
                re.findall(r"synthetic-tracking-(\d+)", capture.body)
            )
            member_names.update(
                re.findall(r"synthetic-member-(\d+)", capture.body)
            )
            ban_uid_a.update(re.findall(r"A=(40\d{5})", capture.body))
            ban_reason_count = max(
                ban_reason_count,
                count_synthetic_bans_in_html(capture.body),
            )
        ban_uid_a = {
            uid_a
            for uid_a in ban_uid_a
            if SYNTHETIC_BAN_MIN <= int(uid_a) <= SYNTHETIC_BAN_MAX
        }
        try:
            captures.append(probe.request("synthetic-pagination-logout", "logout"))
        except (OSError, httpx2.RequestError) as error:
            failures.append(
                {
                    "route": "synthetic-pagination-logout",
                    "error": str(error),
                }
            )
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append(
            {
                "route": "synthetic-pagination-verification",
                "error": str(error),
            }
        )

    config_stats = inspect_synthetic_configs(
        DEFAULT_TRACK_DB,
        DEFAULT_MEMBER_DB,
        DEFAULT_GAME_INI,
    )
    page_boundaries = build_page_boundary_summary(captures)
    page_sequence = build_page_sequence_summary(captures)
    summary: dict[str, object] = {
        "config": config_stats,
        "routes": {
            "tracking_names": sorted(tracking_names),
            "tracking_count": len(tracking_names),
            "member_names": sorted(member_names),
            "member_count": len(member_names),
            "ban_uid_a": sorted(ban_uid_a),
            "ban_count": ban_reason_count,
        },
        "page_boundaries": page_boundaries,
        "page_sequence": page_sequence,
        "failures": failures,
    }

    output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(base_url)
    entries = [write_capture(output, capture, sanitizer) for capture in captures]
    (output / "index.json").write_text(
        json.dumps(
            {
                "captures": entries,
                "summary": summary,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def cli() -> None:
    """Manage reversible synthetic RS2 WebAdmin pagination data."""
    configure_logging()


@cli.command("backup")
@click.option(
    "--backup-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_BACKUP_DIR,
    show_default=True,
)
@click.option("--overwrite", is_flag=True)
def backup_command(backup_dir: Path, overwrite: bool) -> None:
    """Back up the three live config files."""
    try:
        backups = backup_config_files(backup_dir, overwrite=overwrite)
    except (OSError, RuntimeError) as error:
        raise click.ClickException(str(error)) from error
    for name, path in backups.items():
        click.echo(f"{name}: {path}")


@cli.command("validate")
@click.option(
    "--count",
    type=click.IntRange(1, MAX_SYNTHETIC_ROWS),
    default=60,
    show_default=True,
)
@click.option(
    "--temp-dir",
    type=click.Path(path_type=Path),
    default=None,
)
def validate_command(count: int, temp_dir: Path | None) -> None:
    """Validate synthetic parser writes only on temporary config copies."""
    try:
        if temp_dir is None:
            with tempfile.TemporaryDirectory(
                prefix="rs2-synthetic-pagination-validation-"
            ) as temp:
                stats = validate_synthetic_configs(count, Path(temp))
        else:
            temp_dir.mkdir(parents=True, exist_ok=True)
            stats = validate_synthetic_configs(count, temp_dir)
    except (OSError, RuntimeError) as error:
        raise click.ClickException(str(error)) from error
    click.echo(json.dumps(stats, sort_keys=True))


@cli.command("seed")
@click.option(
    "--count",
    type=click.IntRange(1, MAX_SYNTHETIC_ROWS),
    default=60,
    show_default=True,
)
@click.option(
    "--backup-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_BACKUP_DIR,
    show_default=True,
)
@click.option(
    "--restart",
    is_flag=True,
    help="Stop the known VNGame process, seed offline, and restart it.",
)
@click.option("--server-map", default="VNTE-CuChi", show_default=True)
def seed_command(
    count: int,
    backup_dir: Path,
    restart: bool,
    server_map: str,
) -> None:
    """Back up, temp-validate, and seed the three live config files."""
    try:
        if restart:
            backups, stats, started_pid = restart_and_seed_synthetic_configs(
                count,
                backup_dir,
                server_map,
            )
        else:
            ensure_server_stopped_for_seed()
            backups, stats = seed_synthetic_configs(count, backup_dir)
            started_pid = 0
    except (OSError, RuntimeError) as error:
        raise click.ClickException(str(error)) from error
    click.echo(json.dumps(stats, sort_keys=True))
    if started_pid:
        click.echo(f"started-pid: {started_pid}")
    for name, path in backups.items():
        click.echo(f"{name}-backup: {path}")


@cli.command("change-level")
@click.option(
    "--base-url",
    default="http://127.0.0.1:8080/ServerAdmin/",
    show_default=True,
)
@click.option("--username", default=None)
@click.option("--password", default=None)
@click.option("--target-map", default=None)
@click.option("--wait-seconds", type=click.IntRange(1, 600), default=90)
def change_level_command(
    base_url: str,
    username: str | None,
    password: str | None,
    target_map: str | None,
    wait_seconds: int,
) -> None:
    """Change to an alternate live map, triggering a config reload."""
    try:
        resolved_username, resolved_password = login_credentials(
            username,
            password,
        )
        destination = change_level(
            base_url,
            resolved_username,
            resolved_password,
            target_map,
            wait_seconds,
        )
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"level changed: {destination}")


@cli.command("verify")
@click.option(
    "--base-url",
    default="http://127.0.0.1:8080/ServerAdmin/",
    show_default=True,
)
@click.option("--username", default=None)
@click.option("--password", default=None)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=DEFAULT_VERIFY_OUTPUT,
    show_default=True,
)
def verify_command(
    base_url: str,
    username: str | None,
    password: str | None,
    output: Path,
) -> None:
    """Verify synthetic data in live configs and WebAdmin route pages."""
    try:
        resolved_username, resolved_password = login_credentials(
            username,
            password,
        )
        summary = verify_live_routes(
            base_url,
            resolved_username,
            resolved_password,
            output,
        )
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        raise click.ClickException(str(error)) from error
    click.echo(json.dumps(summary, sort_keys=True))


@cli.command("boundary")
@click.option(
    "--counts",
    default="0,1,24,25,26,50,1000",
    show_default=True,
)
@click.option(
    "--backup-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_BACKUP_DIR,
    show_default=True,
)
@click.option("--server-map", default="VNTE-CuaViet", show_default=True)
@click.option(
    "--base-url",
    default="http://127.0.0.1:8080/ServerAdmin/",
    show_default=True,
)
@click.option("--username", default=None)
@click.option("--password", default=None)
@click.option("--wait-seconds", type=click.IntRange(1, 600), default=180)
def boundary_command(
    counts: str,
    backup_dir: Path,
    server_map: str,
    base_url: str,
    username: str | None,
    password: str | None,
    wait_seconds: int,
) -> None:
    """Run live synthetic-count boundaries and restore the baseline."""
    try:
        parsed_counts = [
            int(part.strip())
            for part in counts.split(",")
            if part.strip()
        ]
        if not parsed_counts:
            raise RuntimeError("at least one synthetic boundary count is required")
        if any(count < 0 or count > MAX_SYNTHETIC_ROWS for count in parsed_counts):
            raise RuntimeError(
                f"synthetic counts must be between 0 and {MAX_SYNTHETIC_ROWS}"
            )
        validate_baseline_backups(backup_dir)
        resolved_username, resolved_password = login_credentials(
            username,
            password,
        )
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        raise click.ClickException(str(error)) from error

    summaries: list[dict[str, object]] = []
    restoration_error: Exception | None = None
    try:
        for count in parsed_counts:
            try:
                _, stats, started_pid = restart_and_seed_synthetic_configs(
                    count,
                    backup_dir,
                    server_map,
                )
                wait_for_webadmin(base_url, wait_seconds)
                output = (
                    ROOT
                    / "fixtures"
                    / f"phase7-pagination-boundary-{count:04d}"
                )
                summary = verify_live_routes(
                    base_url,
                    resolved_username,
                    resolved_password,
                    output,
                )
                summaries.append(
                    {
                        "count": count,
                        "started_pid": started_pid,
                        "config": stats,
                        "summary": summary,
                    }
                )
            except (
                OSError,
                RuntimeError,
                httpx2.RequestError,
            ) as error:
                summaries.append(
                    {
                        "count": count,
                        "started_pid": None,
                        "failure": str(error),
                    }
                )
    finally:
        try:
            restored_pid = restore_and_restart_baseline(
                backup_dir,
                server_map,
            )
            wait_for_webadmin(base_url, wait_seconds)
        except (
            OSError,
            RuntimeError,
            httpx2.RequestError,
        ) as error:
            restoration_error = error

    result: dict[str, object] = {
        "boundary_runs": summaries,
        "baseline_restored": restoration_error is None,
    }
    if restoration_error is not None:
        result["restoration_error"] = str(restoration_error)
    else:
        result["restored_pid"] = restored_pid
    click.echo(json.dumps(result, sort_keys=True))


@cli.command("restore")
@click.option(
    "--backup-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_BACKUP_DIR,
    show_default=True,
)
@click.option("--change-level", "change_level_after_restore", is_flag=True)
@click.option(
    "--base-url",
    default="http://127.0.0.1:8080/ServerAdmin/",
    show_default=True,
)
@click.option("--username", default=None)
@click.option("--password", default=None)
@click.option("--wait-seconds", type=click.IntRange(1, 600), default=90)
def restore_command(
    backup_dir: Path,
    change_level_after_restore: bool,
    base_url: str,
    username: str | None,
    password: str | None,
    wait_seconds: int,
) -> None:
    """Restore exact live config backups, optionally after changing level."""
    try:
        backups = backup_mapping_for_dir(backup_dir)
        restore_config_files(backups)
        if change_level_after_restore:
            resolved_username, resolved_password = login_credentials(
                username,
                password,
            )
            destination = change_level(
                base_url,
                resolved_username,
                resolved_password,
                None,
                wait_seconds,
            )
            click.echo(f"level changed after restore: {destination}")
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        raise click.ClickException(str(error)) from error


if __name__ == "__main__":
    cli()
