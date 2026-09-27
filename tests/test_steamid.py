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

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# TODO: what the fuck even is this?
_steamid_path = (
    Path(__file__).resolve().parent.parent / "rs2wapy" / "steam" / "steamid.py"
)
_spec = importlib.util.spec_from_file_location("rs2wapy.steam.steamid", _steamid_path)
assert _spec is not None and _spec.loader is not None
_steamid_mod = importlib.util.module_from_spec(_spec)
sys.modules["rs2wapy.steam.steamid"] = _steamid_mod
_spec.loader.exec_module(_steamid_mod)

EInstanceFlag = _steamid_mod.EInstanceFlag
EType = _steamid_mod.EType
ETypeChar = _steamid_mod.ETypeChar
EUniverse = _steamid_mod.EUniverse
SteamID = _steamid_mod.SteamID
from_csgo_friend_code = _steamid_mod.from_csgo_friend_code
from_invite_code = _steamid_mod.from_invite_code
from_url = _steamid_mod.from_url
make_steam64 = _steamid_mod.make_steam64
steam2_to_tuple = _steamid_mod.steam2_to_tuple
steam3_to_tuple = _steamid_mod.steam3_to_tuple
steam64_from_url = _steamid_mod.steam64_from_url


def test_default_steamid_is_invalid():
    s = SteamID()
    assert int(s) == 0
    assert s.id == 0
    assert s.account_id == 0
    assert s.as_32 == 0
    assert s.as_64 == 0
    assert s.type == EType.Invalid
    assert s.universe == EUniverse.Invalid
    assert not s.is_valid()


@pytest.mark.parametrize("account_id_input", [22202, "22202"])
def test_account_id_initialization(account_id_input):
    s = SteamID(account_id_input)
    assert s.id == 22202
    assert s.account_id == 22202
    assert s.type == EType.Individual
    assert s.universe == EUniverse.Public
    assert s.instance == 1
    assert s.as_64 == 76561197960287930
    assert s.is_valid()


@pytest.mark.parametrize("steam64_input", [76561197960287930, "76561197960287930"])
def test_steam64_initialization_and_formatting(steam64_input):
    s = SteamID(steam64_input)
    assert s.id == 22202
    assert s.as_64 == 76561197960287930
    assert s.as_steam2 == "STEAM_1:0:11101"
    assert s.as_steam2_zero == "STEAM_0:0:11101"
    assert s.as_steam3 == "[U:1:22202]"
    assert str(s) == "76561197960287930"
    assert "SteamID(id=22202" in repr(s)


@pytest.mark.parametrize(
    "steam2_text, expected_steam64, expected_id",
    [
        ("STEAM_1:0:11101", 76561197960287930, 22202),
        ("STEAM_0:0:11101", 76561197960287930, 22202),
        ("STEAM_1:1:11101", 76561197960287931, 22203),
    ],
)
def test_steam2_input(steam2_text, expected_steam64, expected_id):
    s = SteamID(steam2_text)
    assert s.as_64 == expected_steam64
    assert s.id == expected_id


@pytest.mark.parametrize(
    "steam3_text, expected_type, expected_universe, expected_id, expected_instance",
    [
        ("[U:1:22202]", EType.Individual, EUniverse.Public, 22202, 1),
        ("[U:1:22202:2]", EType.Individual, EUniverse.Public, 22202, 2),
        ("[g:1:4]", EType.Clan, EUniverse.Public, 4, 0),
        ("[A:1:123:456]", EType.AnonGameServer, EUniverse.Public, 123, 456),
        ("[c:1:100]", EType.Chat, EUniverse.Public, 100, int(EInstanceFlag.Clan)),
        ("[L:1:100]", EType.Chat, EUniverse.Public, 100, int(EInstanceFlag.Lobby)),
        ("[T:1:100]", EType.Chat, EUniverse.Public, 100, 0),
    ],
)
def test_steam3_input(
    steam3_text, expected_type, expected_universe, expected_id, expected_instance
):
    s = SteamID(steam3_text)
    assert s.type == expected_type
    assert s.universe == expected_universe
    assert s.id == expected_id
    assert s.instance == expected_instance
    assert s.as_steam3 == steam3_text


def test_positional_and_kwargs_initialization():
    s1 = SteamID(22202, EType.Individual, EUniverse.Public, 1)
    assert s1.as_64 == 76561197960287930

    s2 = SteamID(id=22202, type="Individual", universe="Public", instance=1)
    assert s2.as_64 == 76561197960287930

    s3 = SteamID(22202, "Individual", "Public")
    assert s3.as_64 == 76561197960287930

    s4 = SteamID(22202, "Individual")
    assert s4.type == EType.Individual


def test_invalid_argument_errors():
    with pytest.raises(TypeError, match=r"Takes at most 4 arguments"):
        SteamID(1, 2, 3, 4, 5)

    with pytest.raises(ValueError, match=r"instance larger than 20bits"):
        make_steam64(
            id=1, type=EType.Individual, universe=EUniverse.Public, instance=0x1000000
        )


@pytest.mark.parametrize(
    "invite_input",
    [
        "hj-qp",
        "https://s.team/p/hj-qp",
    ],
)
def test_invite_code(invite_input):
    s = SteamID(76561197960287930)
    assert s.as_invite_code == "hj-qp"
    assert s.invite_url == "https://s.team/p/hj-qp"

    s_from_invite = SteamID.from_invite_code(invite_input)
    assert s_from_invite == s


@pytest.mark.parametrize("invalid_invite", ["", "invalid_code_!!!"])
def test_invalid_invite_code_returns_none(invalid_invite):
    assert SteamID.from_invite_code(invalid_invite) is None


def test_csgo_friend_code():
    s = SteamID(76561197960287930)
    code = s.as_csgo_friend_code
    assert code == "SUCVS-FADA"

    s_from_code = SteamID.from_csgo_friend_code(code)
    assert s_from_code == s


@pytest.mark.parametrize("invalid_code", ["INVALID", "12345-6789"])
def test_invalid_csgo_friend_code_returns_none(invalid_code):
    assert SteamID.from_csgo_friend_code(invalid_code) is None


def test_community_url():
    s_ind = SteamID(76561197960287930)
    assert (
        s_ind.community_url == "https://steamcommunity.com/profiles/76561197960287930"
    )

    s_clan = SteamID("[g:1:4]")
    assert s_clan.community_url == f"https://steamcommunity.com/gid/{s_clan.as_64}"

    s_anon = SteamID("[A:1:123:456]")
    assert s_anon.community_url is None


@pytest.mark.parametrize(
    "steam_id_instance, is_valid_expected",
    [
        (SteamID(), False),
        (SteamID(76561197960287930), True),
        (
            SteamID(
                id=22202, type=EType.Individual, universe=EUniverse.Public, instance=5
            ),
            False,
        ),
        (SteamID(id=4, type=EType.Clan, universe=EUniverse.Public, instance=1), False),
        (
            SteamID(id=0, type=EType.GameServer, universe=EUniverse.Public, instance=1),
            False,
        ),
        (
            SteamID(
                id=0, type=EType.AnonGameServer, universe=EUniverse.Public, instance=0
            ),
            False,
        ),
    ],
)
def test_is_valid_validation_rules(steam_id_instance, is_valid_expected):
    assert steam_id_instance.is_valid() == is_valid_expected


def test_steam_url_parsing(monkeypatch):
    assert steam64_from_url("invalid_url") is None

    fake_profile_html = '<html><script>g_rgProfileData = {"steamid": "76561197960287930"};\n</script></html>'
    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_profile_html.encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=30: mock_resp)

    s64 = steam64_from_url("https://steamcommunity.com/id/custom_name")
    assert s64 == 76561197960287930

    sid = SteamID.from_url("https://steamcommunity.com/id/custom_name")
    assert sid == SteamID(76561197960287930)

    fake_group_html = (
        "<html><script>OpenGroupChat('103582791429521412');</script></html>"
    )
    mock_group_resp = MagicMock()
    mock_group_resp.read.return_value = fake_group_html.encode("utf-8")
    mock_group_resp.__enter__.return_value = mock_group_resp

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=30: mock_group_resp
    )

    s64_group = steam64_from_url("https://steamcommunity.com/groups/Valve")
    assert s64_group == 103582791429521412


def test_etype_chars():
    assert str(ETypeChar.U) == "U"
    assert str(ETypeChar.g) == "g"
    assert ETypeChar["U"] == EType.Individual
