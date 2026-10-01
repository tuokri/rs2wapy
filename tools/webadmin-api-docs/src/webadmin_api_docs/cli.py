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
