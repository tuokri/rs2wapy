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

"""Small generators for believable, explicitly synthetic debug-panel data."""

from __future__ import annotations

from random import SystemRandom
from typing import Literal

PlayerIdentityKind = Literal["steam", "egs"]

_random = SystemRandom()

# These deliberately resemble ordinary multiplayer handles, not display names
# sourced from a real player service. Keeping the components small makes the
# generated result varied without adding a data-file dependency.
_NAME_STEMS = (
    "Alex",
    "Bishop",
    "Cobra",
    "Duke",
    "Eagle",
    "Falcon",
    "Gunner",
    "Havoc",
    "Justin",
    "Kilo",
    "Lynx",
    "Mark",
    "Mason",
    "Maverick",
    "Nomad",
    "Ranger",
    "Raven",
    "Rook",
    "Sarge",
    "Scout",
    "Viper",
    "Warden",
    "Wolf",
)
_NAME_PREFIXES = ("", "x", "The", "iAm", "Its", "xX_", "[VN] ")
_NAME_JOINERS = ("", "", "", "_", "-")
_NAME_SYMBOLS = ("#", "!", ".", "~")

STEAM_ID64_BASE = 76_561_197_960_265_728
EGS_ID_MIN = 100_000
EGS_ID_MAX = 1_999_999


def generate_player_name() -> str:
    """Generate a compact synthetic username suitable for mock fixtures."""
    stem = _random.choice(_NAME_STEMS)
    style = _random.randrange(5)
    if style == 0:
        return f"{_random.choice(_NAME_PREFIXES)}{stem}{_random.randrange(10, 100)}"
    if style == 1:
        return f"{stem}{_random.choice(_NAME_SYMBOLS)}{_random.randrange(100, 10_000)}"
    if style == 2:
        other = _random.choice(_NAME_STEMS)
        return f"{stem}{_random.choice(_NAME_JOINERS)}{other}"
    if style == 3:
        return f"{stem} {_random.choice(_NAME_STEMS)}"
    return stem


def generate_player_id(kind: PlayerIdentityKind, existing_ids: set[str]) -> str:
    """Generate an unused SteamID64 or synthetic EGS-like numeric identifier."""
    for _ in range(100):
        if kind == "steam":
            candidate = str(STEAM_ID64_BASE + _random.randrange(1, 2**32))
        else:
            candidate = str(_random.randint(EGS_ID_MIN, EGS_ID_MAX))
        if candidate not in existing_ids:
            return candidate
    raise ValueError("Could not generate an unused player ID")


def unique_id_for_player_id(player_id: str, kind: PlayerIdentityKind) -> str:
    """Return the mock's UE3-style unique-ID projection for an account ID."""
    if kind == "steam":
        try:
            steam_id = int(player_id, 10)
        except ValueError as error:
            raise ValueError("Steam ID must be a decimal SteamID64") from error
        if not STEAM_ID64_BASE <= steam_id < STEAM_ID64_BASE + 2**32:
            raise ValueError("Steam ID must be an individual public SteamID64")
        return f"0x{steam_id:016X}"

    try:
        egs_id = int(player_id, 10)
    except ValueError as error:
        raise ValueError("EGS ID must be a decimal numeric ID") from error
    if egs_id <= 0:
        raise ValueError("EGS ID must be greater than zero")
    # Tripwire's EGS allocation scheme is private. This retains a typed, stable
    # mock unique ID without pretending that the number is an Epic account ID.
    return f"mock-egs-{egs_id}"


def bot_name(name: str) -> str:
    """Apply the required, single BOT prefix to a runtime bot name."""
    base_name = name.strip()
    while base_name.casefold().startswith("bot "):
        base_name = base_name[4:].lstrip()
    if not base_name:
        raise ValueError("Player name is required")
    return f"BOT {base_name}"
