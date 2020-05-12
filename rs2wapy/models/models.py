from __future__ import annotations

import abc
import datetime
import sys
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Type
from typing import Union

from logbook import Logger
from logbook import StreamHandler
from steam.steamid import SteamID

from rs2wapy.adapters import adapters
from rs2wapy.steam import SteamWebAPI

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)


class Model(abc.ABC):
    def __init__(self):
        self._timestamp = datetime.datetime.now()

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: datetime.datetime):
        self._timestamp = timestamp

    def refresh(self):
        """Update timestamp value."""
        self.timestamp = datetime.datetime.now()


HEX_COLOR_BLUE_TEAM = "#50A0F0"
HEX_COLOR_RED_TEAM = "#E54927"
HEX_COLOR_UNKNOWN_TEAM = "transparent"
HEX_COLOR_ALL_TEAM = ""


class Team(abc.ABC):
    HEX_COLOR: Optional[str] = None

    @staticmethod
    def from_hex_color(hex_color: str) -> Type[Team]:
        return HEX_COLOR_TO_TEAM[hex_color]

    @staticmethod
    def from_team_index(index: int) -> Type[Team]:
        try:
            return TEAM_INDEX_TO_TEAM[index]
        except KeyError:
            return UnknownTeam


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

TEAM_INDEX_TO_TEAM: Dict[int, Type[Team]] = {
    0: RedTeam,
    1: BlueTeam,
}

TEAM_TO_TEAM_INDEX: Dict[Type[Team], int] = {
    RedTeam: 0,
    BlueTeam: 1,
}


class Player(Model):
    def __init__(self, steam_id: Union[SteamID, int, str], stats: dict = None,
                 persona_name: str = None, id_intstr_base: int = 16):
        super().__init__()

        if not stats:
            stats = {}
        self._stats = stats

        if isinstance(steam_id, SteamID):
            self._steam_id = steam_id
        elif isinstance(steam_id, int):
            self._steam_id = SteamID(steam_id)
        elif isinstance(steam_id, str):
            self._steam_id = SteamID(int(steam_id, id_intstr_base))
        else:
            raise ValueError(
                f"invalid steam_id type: {type(steam_id)}, expected "
                f"{Union[SteamID, int, str]}")

        self._persona_name = persona_name

    @property
    def stats(self) -> dict:
        return self._stats

    @property
    def steam_id(self) -> SteamID:
        return self._steam_id

    @property
    def name(self) -> str:
        """Player's name as stored in RS2 WebAdmin."""
        try:
            return self.stats["Player name"]
        except KeyError as ke:
            logger.debug(ke, exc_info=True)
            logger.warn(f"unable to get player name for Steam ID {self.steam_id}")
            return ""

    @property
    def persona_name(self) -> str:
        """Player's Steam persona (profile) name."""
        if self._persona_name is None:
            self._persona_name = SteamWebAPI().get_persona_name(self.steam_id)
        return self._persona_name

    def __str__(self) -> str:
        steam_id = (self._steam_id.as_64
                    if isinstance(self._steam_id, SteamID)
                    else self._steam_id)
        return f"SteamID64={steam_id}"

    def __repr__(self) -> str:
        return f"Player({self.__str__()})"

    def __hash__(self) -> int:
        return self._steam_id.as_64


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
        # noinspection PyTypeChecker
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
    def __init__(self,
                 sender: Union[Player, adapters.PlayerWrapper, str],
                 text: str,
                 team: Type[Team], channel: Type[ChatChannel]):
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
        return f"{type(self).__name__}({self.__str__()})"

    @property
    def sender(self) -> Union[Player, adapters.PlayerWrapper, str]:
        return self._sender

    @property
    def text(self) -> str:
        return self._text

    @property
    def team(self) -> Type[Team]:
        return self._team

    @property
    def channel(self) -> Type[ChatChannel]:
        return self._channel


class Scoreboard(abc.ABC):
    def __init__(self, stats: dict):
        self._stats = stats

    def __str__(self) -> str:
        return self._stats.__str__()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__str__()})"


class PlayerScoreboard(Scoreboard):
    pass


class TeamScoreboard(Scoreboard):
    pass


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
    def __init__(self, ip_mask: str, policy):
        super().__init__()
        self._ip_mask = ip_mask
        self._policy = policy


class MapCycle(Model):
    def __init__(self, maps: List[Tuple[str, int]], active: bool):
        super().__init__()
        self._maps = maps
        self._active = active

    @property
    def active(self) -> bool:
        return self._active

    @active.setter
    def active(self, active: bool):
        self._active = active

    @property
    def maps(self) -> List[Tuple[str, int]]:
        return self._maps

    @maps.setter
    def maps(self, maps: List[Tuple[str, int]]):
        self._maps = maps

    def __str__(self) -> str:
        return f"{self._maps}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__str__()})"


class Squad(Model):
    def __init__(self, team: Type[Team], number: int, name: str):
        super().__init__()
        self._team = team
        self._number = number
        self._name = name

    def __str__(self) -> str:
        return f"team={self._team}, number={self._number}, name={self._name}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__str__()})"

    def __hash__(self) -> int:
        return self._number


class Ban(Model):
    def __init__(self, player: Player, reason: str,
                 until: Union[str, datetime.datetime] = None):
        super().__init__()
        self._player = player
        self._reason = reason

        if isinstance(until, str):
            until = self._parse_until(until)
        self._until = until

    @property
    def player(self) -> Player:
        return self._player

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def until(self) -> Optional[datetime.datetime]:
        """Ban expiration date. If None, the ban is permanent."""
        return self._until

    @property
    def expired(self) -> bool:
        """True if ban has expired."""
        if self.until is not None:
            return self.until > datetime.datetime.now()
        else:
            return False

    @staticmethod
    def _parse_until(until: str) -> datetime.datetime:
        """Ban expiration date str to datetime.datetime object."""
        # TODO:
        return datetime.datetime.strptime(until, "")


class SessionBan(Ban):
    def __init__(self, player: Player, reason: str):
        super().__init__(player, reason, None)
        self._until = None
