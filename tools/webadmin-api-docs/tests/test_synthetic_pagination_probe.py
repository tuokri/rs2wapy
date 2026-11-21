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

"""Focused tests for synthetic pagination config seeding."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from synthetic_pagination_probe import DEFAULT_BACKUP_DIR
from synthetic_pagination_probe import count_route_row_fields
from synthetic_pagination_probe import count_synthetic_bans_in_html
from synthetic_pagination_probe import count_synthetic_route_markers
from synthetic_pagination_probe import extract_hidden_index
from synthetic_pagination_probe import inspect_synthetic_configs
from synthetic_pagination_probe import prepare_synthetic_temp_files
from synthetic_pagination_probe import remove_synthetic_bans
from synthetic_pagination_probe import remove_synthetic_table_entries
from synthetic_pagination_probe import synthetic_member_rows
from synthetic_pagination_probe import synthetic_tracking_rows


def test_synthetic_rows_have_unique_markers_and_bans() -> None:
    players, punks, bans = synthetic_tracking_rows(3)
    members = synthetic_member_rows(3)

    assert len(players) == len(punks) == len(members) == len(bans) == 3
    assert "synthetic-tracking-001" in players[0]
    assert "synthetic-punk-003" in punks[2]
    assert "synthetic-member-002" in members[1]
    assert "A=40000003,B=17825793" in bans[2]


def test_synthetic_rows_support_6000_rows() -> None:
    players, punks, bans = synthetic_tracking_rows(6000)
    members = synthetic_member_rows(6000)

    assert len(players) == len(punks) == len(members) == len(bans) == 6000
    assert "synthetic-tracking-6000" in players[-1]
    assert "synthetic-punk-6000" in punks[-1]
    assert "synthetic-member-6000" in members[-1]
    assert "A=40006000,B=17825793" in bans[-1]


def test_backup_dir_uses_user_home_without_session_state() -> None:
    assert DEFAULT_BACKUP_DIR == (
        Path.home() / ".rs2wapy" / "synthetic-pagination-backups"
    )
    backup_dir_text = str(DEFAULT_BACKUP_DIR)
    assert ".copilot" not in backup_dir_text
    assert "session-state" not in backup_dir_text


def test_synthetic_ban_row_reason_count() -> None:
    html = (
        "<td>Synthetic pagination ban</td>"
        "<td>Server-ban synchronization</td>"
        "<td>Synthetic pagination ban</td>"
    )

    assert count_synthetic_bans_in_html(html) == 2


def test_page_boundary_helpers() -> None:
    tracking = (
        '<input name="__FirstVisibleRowIndex" value="25"/>'
        '<input name="__CurrentTabIndex" value="0"/>'
        '<input name="__PlayerName_25" value="synthetic-tracking-026"/>'
        '<input name="__PlayerName_26" value="synthetic-tracking-027"/>'
        '<span>synthetic-tracking-026</span>'
        '<span>synthetic-tracking-027</span>'
        '<span>synthetic-tracking-1000</span>'
    )
    members = (
        '<input name="__MemberName_25" value="synthetic-member-026"/>'
        '<input name="__MemberName_26" value="synthetic-member-027"/>'
    )
    bans = (
        "<td>Synthetic pagination ban</td>"
        "<td>Synthetic pagination ban</td>"
    )

    assert extract_hidden_index(tracking, "__FirstVisibleRowIndex") == 25
    assert extract_hidden_index(tracking, "__CurrentTabIndex") == 0
    assert count_route_row_fields(tracking, "policy/tracking") == 2
    assert count_route_row_fields(members, "policy/members") == 2
    assert count_route_row_fields(bans, "policy/bans") == 0
    assert count_synthetic_route_markers(tracking, "policy/tracking") == 3
    assert count_synthetic_route_markers(members, "policy/members") == 2
    assert count_synthetic_route_markers(bans, "policy/bans") == 2


def test_synthetic_cleanup_preserves_real_rows() -> None:
    real_player = '(PlayerID="real",PlayerNames=("real-player"))'
    real_member = '(MemberId="real",MemberName="real-member")'
    dirty_players = [
        real_player,
        '(PlayerID="synthetic",PlayerNames=("synthetic-tracking-001"))',
        '(PlayerID="dummy",PlayerNames=("xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE"))',
    ]
    dirty_members = [
        real_member,
        '(MemberId="synthetic",MemberName="synthetic-member-001")',
    ]
    dirty_bans = [
        "(Uid=(A=123456,B=17825793))",
        "(Uid=(A=40000001,B=17825793))",
        "(Uid=(A=0,B=0))",
    ]

    assert remove_synthetic_table_entries(dirty_players, "synthetic-tracking") == [
        real_player
    ]
    assert remove_synthetic_table_entries(dirty_members, "synthetic-member") == [
        real_member
    ]
    assert remove_synthetic_bans(dirty_bans) == [
        "(Uid=(A=123456,B=17825793))"
    ]


def test_temp_parser_write_preserves_real_rows_and_writes_three_lists(
    tmp_path: Path,
) -> None:
    track_source = tmp_path / "ROTrackDb.ini"
    member_source = tmp_path / "ROMemberDb.ini"
    game_source = tmp_path / "ROGame.ini"
    track_source.write_text(
        "[ROGame.TrackDb]\n"
        'Table_Players=(PlayerID="real-player")\n'
        'Table_Punks=(PunkId="real-punk")\n',
        encoding="utf-8",
    )
    member_source.write_text(
        "[ROGame.MemberDb]\n"
        'Table_Members=(MemberId="real-member")\n',
        encoding="utf-8",
    )
    game_source.write_text(
        "[Engine.AccessControl]\n"
        "BannedIDs=(Uid=(A=123456,B=17825793))\n"
        "BannedIDs=(Uid=(A=40000001,B=17825793))\n",
        encoding="utf-8",
    )

    temp_dir = tmp_path / "temp"
    temp_files = prepare_synthetic_temp_files(
        3,
        temp_dir,
        track_source=track_source,
        member_source=member_source,
        game_source=game_source,
    )
    stats = inspect_synthetic_configs(
        temp_files["track"],
        temp_files["members"],
        temp_files["game"],
    )

    assert stats == {
        "tracking_players": 3,
        "tracking_punks": 3,
        "members": 3,
        "bans": 3,
    }
    assert 'PlayerID="real-player"' in temp_files["track"].read_text(
        encoding="utf-8"
    )
    assert 'MemberId="real-member"' in temp_files["members"].read_text(
        encoding="utf-8"
    )
    assert "A=123456,B=17825793" in temp_files["game"].read_text(
        encoding="utf-8"
    )
