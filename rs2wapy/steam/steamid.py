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
#
# Module adapted and modernized from https://pypi.org/project/steam/.
# See: https://github.com/ValvePython/steam/blob/master/steam/steamid.py.
#
# Copyright (c) 2015 Rossen Georgiev <rossen@rgp.io>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
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

from __future__ import annotations

import hashlib
import json
import re
import struct
import urllib.error
import urllib.request
from enum import IntEnum
from enum import IntFlag
from typing import Any

from rs2wapy import __version__


class EUniverse(IntEnum):
    Invalid = 0
    Public = 1
    Beta = 2
    Internal = 3
    Dev = 4
    Max = 5


class EType(IntEnum):
    Invalid = 0
    Individual = 1
    Multiseat = 2
    GameServer = 3
    AnonGameServer = 4
    Pending = 5
    ContentServer = 6
    Clan = 7
    Chat = 8
    ConsoleUser = 9
    AnonUser = 10
    Max = 11


class EInstanceFlag(IntFlag):
    MMSLobby = 0x20000
    Lobby = 0x40000
    Clan = 0x80000


class ETypeChar(IntEnum):
    I = EType.Invalid  # noqa: E741
    U = EType.Individual
    M = EType.Multiseat
    G = EType.GameServer
    A = EType.AnonGameServer
    P = EType.Pending
    C = EType.ContentServer
    g = EType.Clan
    T = EType.Chat
    L = EType.Chat  # lobby chat, 'c' for clan chat
    c = EType.Chat  # clan chat
    a = EType.AnonUser

    def __str__(self) -> str:
        return self.name


ETypeChars = "".join(ETypeChar.__members__.keys())

_icode_hex = "0123456789abcdef"
_icode_custom = "bcdfghjkmnpqrtvw"
_icode_all_valid = _icode_hex + _icode_custom
_icode_map = dict(zip(_icode_hex, _icode_custom))
_icode_map_inv = dict(zip(_icode_custom, _icode_hex))
_csgofrcode_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class SteamID(int):
    """Object for converting steamID to its various representations.

    .. code:: python

        SteamID()  # invalid steamid
        SteamID(12345)  # accountid
        SteamID('12345')
        SteamID(id=12345, type='Invalid', universe='Invalid', instance=0)
        SteamID(103582791429521412)  # steam64
        SteamID('103582791429521412')
        SteamID('STEAM_1:0:2')  # steam2
        SteamID('[g:1:4]')  # steam3
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> SteamID:
        steam64 = make_steam64(*args, **kwargs)
        return super().__new__(cls, steam64)

    def __str__(self) -> str:
        return str(int(self))

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(id={self.id}, type={self.type.name!r}, "
            f"universe={self.universe.name!r}, instance={self.instance})"
        )

    @property
    def id(self) -> int:
        """Account ID."""
        return int(self) & 0xFFFFFFFF

    @property
    def account_id(self) -> int:
        """Account ID."""
        return int(self) & 0xFFFFFFFF

    @property
    def instance(self) -> int:
        """Account instance."""
        return (int(self) >> 32) & 0xFFFFF

    @property
    def type(self) -> EType:
        """Account type."""
        val = (int(self) >> 52) & 0xF
        try:
            return EType(val)
        except ValueError:
            return EType.Invalid

    @property
    def universe(self) -> EUniverse:
        """Steam universe."""
        val = (int(self) >> 56) & 0xFF
        try:
            return EUniverse(val)
        except ValueError:
            return EUniverse.Invalid

    @property
    def as_32(self) -> int:
        """Account ID as 32-bit integer."""
        return self.id

    @property
    def as_64(self) -> int:
        """Steam64 format."""
        return int(self)

    @property
    def as_steam2(self) -> str:
        """Steam2 format (e.g. ``STEAM_1:0:1234``)."""
        return f"STEAM_{int(self.universe)}:{self.id % 2}:{self.id >> 1}"

    @property
    def as_steam2_zero(self) -> str:
        """For GoldSrc and Orange Box games (e.g. ``STEAM_0:0:1234``)."""
        return self.as_steam2.replace("_1", "_0")

    @property
    def as_steam3(self) -> str:
        """Steam3 format (e.g. ``[U:1:1234]``)."""
        typechar = str(ETypeChar(self.type))
        instance: int | None = None

        if self.type in (EType.AnonGameServer, EType.Multiseat):
            instance = self.instance
        elif self.type == EType.Individual:
            if self.instance != 1:
                instance = self.instance
        elif self.type == EType.Chat:
            if self.instance & EInstanceFlag.Clan:
                typechar = "c"
            elif self.instance & EInstanceFlag.Lobby:
                typechar = "L"
            else:
                typechar = "T"

        parts: list[Any] = [typechar, int(self.universe), self.id]

        if instance is not None:
            parts.append(instance)

        return f"[{':'.join(map(str, parts))}]"

    @property
    def as_invite_code(self) -> str | None:
        """s.team invite code format (e.g. ``cv-dgb``)."""
        if self.type == EType.Individual and self.is_valid():

            def repl_mapper(x: re.Match[str]) -> str:
                return _icode_map[x.group()]

            invite_code = re.sub(f"[{_icode_hex}]", repl_mapper, f"{self.id:x}")
            split_idx = len(invite_code) // 2

            if split_idx:
                invite_code = invite_code[:split_idx] + "-" + invite_code[split_idx:]

            return invite_code
        return None

    @property
    def as_csgo_friend_code(self) -> str | None:
        """CS:GO Friend code (e.g. ``AEBJA-ABDC``)."""
        if self.type != EType.Individual or not self.is_valid():
            return None

        h_bytes = b"CSGO" + struct.pack(">L", self.account_id)
        h_val, = struct.unpack("<L", hashlib.md5(h_bytes[::-1]).digest()[:4])
        steamid = self.as_64
        result = 0

        for i in range(8):
            id_nib = (steamid >> (i * 4)) & 0xF
            hash_nib = (h_val >> i) & 0x1
            a = (result << 4) | id_nib

            result = ((result >> 28) << 32) | a
            result = ((result >> 31) << 32) | ((a << 1) | hash_nib)

        result, = struct.unpack("<Q", struct.pack(">Q", result))
        code = ""

        for i in range(13):
            if i in (4, 9):
                code += "-"

            code += _csgofrcode_chars[result & 31]
            result >>= 5

        return code[5:]

    @property
    def invite_url(self) -> str | None:
        """Invite URL (e.g. ``https://s.team/p/cv-dgb``)."""
        code = self.as_invite_code
        if code:
            return f"https://s.team/p/{code}"
        return None

    @property
    def community_url(self) -> str | None:
        """Community URL (e.g. ``https://steamcommunity.com/profiles/123456789``)."""
        suffix = {
            EType.Individual: "profiles/%s",
            EType.Clan: "gid/%s",
        }
        if self.type in suffix:
            url = f"https://steamcommunity.com/{suffix[self.type]}"
            return url % self.as_64

        return None

    def is_valid(self) -> bool:
        """Check whether this SteamID is valid."""
        if self.type == EType.Invalid or self.type >= EType.Max:
            return False

        if self.universe == EUniverse.Invalid or self.universe >= EUniverse.Max:
            return False

        if self.type == EType.Individual:
            if self.id == 0 or self.instance > 4:
                return False

        if self.type == EType.Clan:
            if self.id == 0 or self.instance != 0:
                return False

        if self.type == EType.GameServer:
            if self.id == 0:
                return False

        if self.type == EType.AnonGameServer:
            if self.id == 0 and self.instance == 0:
                return False

        return True

    @classmethod
    def from_invite_code(cls, code: str, universe: EUniverse = EUniverse.Public) -> SteamID | None:
        """Creates a SteamID from an invite code or URL."""
        return from_invite_code(code, universe)

    @classmethod
    def from_csgo_friend_code(
        cls, code: str, universe: EUniverse = EUniverse.Public
    ) -> SteamID | None:
        """Creates a SteamID from a CS:GO friend code."""
        return from_csgo_friend_code(code, universe)

    @classmethod
    def from_url(cls, url: str, http_timeout: int = 30) -> SteamID | None:
        """Takes Steam community url and returns a SteamID instance or None."""
        return from_url(url, http_timeout)


SteamID.EType = EType  # type: ignore[attr-defined]
SteamID.EUniverse = EUniverse  # type: ignore[attr-defined]
SteamID.EInstanceFlag = EInstanceFlag  # type: ignore[attr-defined]


def make_steam64(id: Any = 0, *args: Any, **kwargs: Any) -> int:
    """Returns steam64 from various other representations.

    .. code:: python

        make_steam64()  # invalid steamid
        make_steam64(12345)  # accountid
        make_steam64('12345')
        make_steam64(id=12345, type='Invalid', universe='Invalid', instance=0)
        make_steam64(103582791429521412)  # steam64
        make_steam64('103582791429521412')
        make_steam64('STEAM_1:0:2')  # steam2
        make_steam64('[g:1:4]')  # steam3
    """
    accountid: int = id
    etype: Any = EType.Invalid
    universe: Any = EUniverse.Invalid
    instance: int | None = None

    if len(args) == 0 and len(kwargs) == 0:
        value = str(accountid)

        # numeric input
        if value.isdigit():
            int_val = int(value)

            # 32 bit account id
            if 0 < int_val < 2**32:
                accountid = int_val
                etype = EType.Individual
                universe = EUniverse.Public
            # 64 bit
            elif int_val < 2**64:
                accountid = int(int_val & 0xFFFFFFFF)
                instance = int((int_val >> 32) & 0xFFFFF)
                etype = int((int_val >> 52) & 0xF)
                universe = int((int_val >> 56) & 0xFF)
            # invalid account id
            else:
                accountid = 0

        # textual input e.g. [g:1:4]
        else:
            result = steam2_to_tuple(value) or steam3_to_tuple(value)

            if result:
                (
                    accountid,
                    etype,
                    universe,
                    instance,
                ) = result
            else:
                accountid = 0

    elif len(args) > 0:
        length = len(args)
        if length == 1:
            etype, = args
        elif length == 2:
            etype, universe = args
        elif length == 3:
            etype, universe, instance = args
        else:
            raise TypeError(f"Takes at most 4 arguments ({length} given)")

    if len(kwargs) > 0:
        etype = kwargs.get("type", etype)
        universe = kwargs.get("universe", universe)
        instance = kwargs.get("instance", instance)

    etype = (
        EType(etype)
        if isinstance(etype, (int, EType))
        else EType[etype]
    )

    universe = (
        EUniverse(universe)
        if isinstance(universe, (int, EUniverse))
        else EUniverse[universe]
    )

    if instance is None:
        instance = 1 if etype in (EType.Individual, EType.GameServer) else 0

    if instance > 0xFFFFF:
        raise ValueError("instance larger than 20bits")

    return (universe << 56) | (etype << 52) | (instance << 32) | accountid


def steam2_to_tuple(value: str) -> tuple[int, EType, EUniverse, int] | None:
    """Converts steam2 format to tuple representation.

    :param value: steam2 (e.g. ``STEAM_1:0:1234``)
    :return: (accountid, type, universe, instance)
    """
    match = re.match(
        r"^STEAM_(?P<universe>\d+):(?P<reminder>[0-1]):(?P<id>\d+)$", value
    )

    if not match:
        return None

    steam32 = (int(match.group("id")) << 1) | int(match.group("reminder"))
    universe = int(match.group("universe"))

    # Games before orange box used to incorrectly display universe as 0, we support that
    if universe == 0:
        universe = 1

    return steam32, EType(1), EUniverse(universe), 1


def steam3_to_tuple(value: str) -> tuple[int, EType, EUniverse, int] | None:
    """Converts steam3 format to tuple representation.

    :param value: steam3 (e.g. ``[U:1:1234]``)
    :return: (accountid, type, universe, instance)
    """
    match = re.match(
        rf"^\[(?P<type>[i{ETypeChars}]):(?P<universe>[0-4]):(?P<id>\d{{1,10}})(:(?P<instance>\d+))?\]$",
        value,
    )
    if not match:
        return None

    steam32 = int(match.group("id"))
    universe = EUniverse(int(match.group("universe")))
    typechar = match.group("type").replace("i", "I")
    etype = EType(ETypeChar[typechar])
    inst_match = match.group("instance")

    if typechar in "gT":
        instance = 0
    elif inst_match is not None:
        instance = int(inst_match)
    elif typechar == "L":
        instance = int(EInstanceFlag.Lobby)
    elif typechar == "c":
        instance = int(EInstanceFlag.Clan)
    elif etype in (EType.Individual, EType.GameServer):
        instance = 1
    else:
        instance = 0

    return steam32, etype, universe, instance


def from_invite_code(code: str, universe: EUniverse = EUniverse.Public) -> SteamID | None:
    """Invites URLs can be generated at https://steamcommunity.com/my/friends/add

    :param code: invite code (e.g. ``https://s.team/p/cv-dgb``, ``cv-dgb``)
    :param universe: Steam universe (default: ``Public``)
    :return: SteamID instance or None
    """
    if not code:
        return None

    m = re.match(
        rf"(https?://s\.team/p/(?P<code1>[\-+{_icode_all_valid}]+))|(?P<code2>[\-+{_icode_all_valid}]+$)",
        code,
    )
    if not m:
        return None

    code_str = (m.group("code1") or m.group("code2")).replace("-", "")

    def repl_mapper(x: re.Match[str]) -> str:
        return _icode_map_inv[x.group()]

    accountid = int(re.sub(f"[{_icode_custom}]", repl_mapper, code_str), 16)

    if 0 < accountid < 2**32:
        return SteamID(accountid, EType.Individual, EUniverse(universe), 1)

    return None


def from_csgo_friend_code(code: str, universe: EUniverse = EUniverse.Public) -> SteamID | None:
    """Takes CS:GO friend code and returns SteamID.

    :param code: CS:GO friend code (e.g. ``AEBJA-ABDC``)
    :param universe: Steam universe (default: ``Public``)
    :return: SteamID instance or None
    """
    if not re.match(rf"^[{_csgofrcode_chars}\-]{{10}}$", code):
        return None

    code_str = ("AAAA-" + code).replace("-", "")
    result = 0

    for i in range(13):
        index = _csgofrcode_chars.find(code_str[i])
        if index == -1:
            return None
        result |= index << (5 * i)

    result, = struct.unpack("<Q", struct.pack(">Q", result))
    accountid = 0

    for _ in range(8):
        result >>= 1
        id_nib = result & 0xF
        result >>= 4
        accountid = (accountid << 4) | id_nib

    return SteamID(accountid, EType.Individual, EUniverse(universe), 1)


def steam64_from_url(url: str, http_timeout: int = 30) -> int | None:
    """Takes a Steam Community url and returns steam64 or None.

    :param url: steam community url
    :param http_timeout: how long to wait on http request before returning None
    :return: steam64, or None if failed
    """
    match = re.match(
        r"^(?P<clean_url>https?://steamcommunity.com/"
        r"(?P<type>profiles|id|gid|groups|user)/(?P<value>.*?))(?:/(?:.*)?)?$",
        url,
    )

    if not match:
        return None

    try:
        req = urllib.request.Request(
            match.group("clean_url"),
            headers={"User-Agent": f"rs2wapy/{__version__}/SteamID"},
        )
        with urllib.request.urlopen(req, timeout=http_timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")

        if match.group("type") in ("id", "profiles", "user"):
            data_match = re.search(r"g_rgProfileData = (?P<json>\{.*?\});[ \t\r]*\n", text)
            if data_match:
                data = json.loads(data_match.group("json"))
                return int(data["steamid"])
        else:
            data_match = re.search(r"OpenGroupChat\( *'(?P<steamid>\d+)'", text)
            if data_match:
                return int(data_match.group("steamid"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError):
        return None

    return None


def from_url(url: str, http_timeout: int = 30) -> SteamID | None:
    """Takes Steam community url and returns a SteamID instance or None."""
    steam64 = steam64_from_url(url, http_timeout)
    if steam64:
        return SteamID(steam64)
    return None
