import abc
import datetime
from typing import List
from typing import Sequence
from typing import Union

from steam import SteamID


# import rs2wapy.adapters


class Model(abc.ABC):
    def __init__(self):
        self._timestamp = datetime.datetime.now()

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: datetime.datetime):
        self._timestamp = timestamp


HEX_COLOR_BLUE_TEAM = "#50A0F0"
HEX_COLOR_RED_TEAM = "#E54927"
HEX_COLOR_UNKNOWN_TEAM = "transparent"
HEX_COLOR_ALL_TEAM = ""


class Team(abc.ABC):
    HEX_COLOR = None

    @staticmethod
    def from_hex_color(hex_color: str):
        return HEX_COLOR_TO_TEAM[hex_color]

    @classmethod
    def to_hex_color(cls) -> str:
        if not cls.HEX_COLOR:
            raise NotImplementedError("not implemented for abstract base class")
        return TEAM_TO_HEX_COLOR[cls.HEX_COLOR]


class BlueTeam(Team):
    HEX_COLOR = HEX_COLOR_BLUE_TEAM


class RedTeam(Team):
    HEX_COLOR = HEX_COLOR_RED_TEAM


class UnknownTeam(Team):
    HEX_COLOR = HEX_COLOR_UNKNOWN_TEAM


class AllTeam(Team):
    HEX_COLOR = HEX_COLOR_ALL_TEAM


HEX_COLOR_TO_TEAM = {
    HEX_COLOR_BLUE_TEAM: BlueTeam,
    HEX_COLOR_RED_TEAM: RedTeam,
    HEX_COLOR_UNKNOWN_TEAM: UnknownTeam,
    HEX_COLOR_ALL_TEAM: AllTeam,
}

TEAM_TO_HEX_COLOR = {
    BlueTeam: HEX_COLOR_BLUE_TEAM,
    RedTeam: HEX_COLOR_RED_TEAM,
    UnknownTeam: HEX_COLOR_UNKNOWN_TEAM,
    AllTeam: HEX_COLOR_ALL_TEAM,
}

_STEAM_ID_TYPE = Union[SteamID, int, str]


class Player(Model):
    def __init__(self, steam_id: _STEAM_ID_TYPE, rs2_name: str):
        super().__init__()

        if isinstance(steam_id, SteamID):
            self._steam_id = steam_id
        elif isinstance(steam_id, int):
            self._steam_id = SteamID(steam_id)
        elif isinstance(steam_id, str):
            self._steam_id = SteamID(int(steam_id, 16))
        else:
            raise ValueError(
                f"invalid steam_id type: {type(steam_id)}, expected "
                f"{_STEAM_ID_TYPE}")
        self._rs2_name = rs2_name

    def __str__(self) -> str:
        steam_id = (self._steam_id.as_64
                    if isinstance(self._steam_id, SteamID)
                    else self._steam_id)
        return f"SteamID64={steam_id}"

    def __repr__(self) -> str:
        return f"Player({self.__str__()})"

    def ban(self, adapter):
        print(adapter)

    def whisper(self):
        pass


CHAT_CHANNEL_ALL_STR = "(ALL)"
CHAT_CHANNEL_TEAM_STR = "(TEAM)"
TEAMNOTICE_TEAM = CHAT_CHANNEL_TEAM_STR


class ChatChannel(abc.ABC):
    @staticmethod
    def from_teamnotice(teamnotice: str):
        try:
            teamnotice = teamnotice.upper()
        except AttributeError:
            pass
        return TEAMNOTICE_TO_CHAT_CHANNEL[teamnotice]

    @classmethod
    def to_team_str(cls) -> str:
        return CHAT_CHANNEL_TO_STR[cls]


class ChatChannelAll(ChatChannel):
    pass


class ChatChannelTeam(ChatChannel):
    pass


TEAMNOTICE_TO_CHAT_CHANNEL = {
    None: ChatChannelAll,
    TEAMNOTICE_TEAM: ChatChannelTeam,
}

CHAT_CHANNEL_TO_STR = {
    ChatChannelAll: CHAT_CHANNEL_ALL_STR,
    ChatChannelTeam: CHAT_CHANNEL_TEAM_STR,
}


class ChatMessage(Model):
    def __init__(self, sender: Union[Player, str], text: str,
                 team: Team, channel: ChatChannel):
        super().__init__()
        self._sender = sender
        self._text = text
        self._team = team
        self._channel = channel

    def __str__(self) -> str:
        if isinstance(self._team, UnknownTeam):
            channel = f"({self._channel.to_team_str()})"
        else:
            channel = f"({self._team.__name__}) {self._channel.to_team_str()}"
        return f"{self._timestamp.isoformat()} {self._sender} {channel}: {self._text}"

    def __repr__(self) -> str:
        return f"{__class__.__name__}({self.__str__()})"


class Scoreboard(list, abc.ABC):
    def __init__(self, seq: Sequence = (), header: List[str] = None):
        super().__init__(seq)
        if not header:
            header = []
        self._header = header

    @property
    def header(self) -> List[str]:
        return self._header

    @header.setter
    def header(self, header: List[str]):
        self._header = header


class PlayerScoreboard(Scoreboard):
    """
    PlayerScoreboard does not store player IDs because deducing
    them from WebAdmin scoreboard is not reliable.
    """

    def __init__(self, seq: Sequence = (), header: List[str] = None):
        super().__init__(seq, header)


class TeamScoreboard(Scoreboard):
    def __init__(self, seq: Sequence = (), header: List[str] = None):
        super().__init__(seq, header)


class CurrentGame(Model):
    def __init__(self, player_scoreboard: PlayerScoreboard,
                 team_scoreboard: TeamScoreboard,
                 info: dict, rules: dict):
        super().__init__()
        self._player_scoreboard = player_scoreboard
        self._team_scoreboard = team_scoreboard
        self._info = info
        self._rules = rules

    @property
    def player_scoreboard(self) -> PlayerScoreboard:
        return self._player_scoreboard

    @player_scoreboard.setter
    def player_scoreboard(self, scoreboard: PlayerScoreboard):
        self._player_scoreboard = scoreboard

    @property
    def team_scoreboard(self) -> TeamScoreboard:
        return self._team_scoreboard

    @team_scoreboard.setter
    def team_scoreboard(self, scoreboard: TeamScoreboard):
        self._team_scoreboard = scoreboard

    @property
    def ranked(self) -> bool:
        return self._info["Ranked"]

    @ranked.setter
    def ranked(self, ranked: bool):
        self._info["Ranked"] = ranked

    @property
    def info(self) -> dict:
        return self._info

    @info.setter
    def info(self, info: dict):
        self._info = info

    @property
    def rules(self) -> dict:
        return self._rules

    @rules.setter
    def rules(self, rules: dict):
        self._rules = rules


class AccessPolicy(Model):
    pass
