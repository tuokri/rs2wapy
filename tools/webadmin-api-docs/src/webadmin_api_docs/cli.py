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

"""Shared typed values and Click helpers for discovery-tool command lines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import click

CLICK_CONTEXT_SETTINGS: dict[str, list[str]] = {"help_option_names": ["-h", "--help"]}


@dataclass(frozen=True, slots=True)
class ToolArguments:
    """Superset of stable options accepted by the standalone discovery tools."""

    base_url: str
    output: Path
    username: str = ""
    password: str = ""
    primary_username: str = ""
    primary_password: str = ""
    secondary_username: str = ""
    secondary_password: str = ""
    disabled_username: str = ""
    disabled_password: str = ""
    restricted_username: str = ""
    restricted_password: str = ""
    player_name: str = ""
    second_player_name: str = ""
    wait_seconds: int = 54
    write_chat: bool = False
    policy_roundtrip: bool = False
    permanent_ban_roundtrip: bool = False


def exit_with_status(status: int) -> NoReturn:
    """Exit a Click command with the legacy process status code."""
    raise click.exceptions.Exit(status)
