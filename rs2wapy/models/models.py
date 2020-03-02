import abc
import collections
import datetime
from abc import abstractmethod
from typing import Iterable
from typing import List
from typing import MutableSequence
from typing import Union
from typing import overload

from steam import SteamID

_STEAM_ID_TYPE = Union[SteamID, int, str]


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


HEX_COLOR_TO_TEAM = {
    HEX_COLOR_BLUE_TEAM: BlueTeam,
    HEX_COLOR_RED_TEAM: RedTeam,
    HEX_COLOR_UNKNOWN_TEAM: UnknownTeam,
}

TEAM_TO_HEX_COLOR = {
    BlueTeam: HEX_COLOR_BLUE_TEAM,
    RedTeam: HEX_COLOR_RED_TEAM,
    UnknownTeam: HEX_COLOR_UNKNOWN_TEAM,
}


class Player(Model):
    def __init__(self, steam_id: _STEAM_ID_TYPE, rs2_unique_id: Union[int, str],
                 rs2_name: str):
        super().__init__()
        if isinstance(steam_id, SteamID):
            self._steam_id = steam_id
        elif isinstance(steam_id, (int, str)):
            self._steam_id = SteamID(steam_id)
        else:
            raise ValueError(
                f"invalid steam_id type: {type(steam_id)}, expected "
                f"{_STEAM_ID_TYPE}")
        if isinstance(rs2_unique_id, str):
            rs2_unique_id = int(rs2_unique_id, 16)
        self._rs2_unique_id = rs2_unique_id
        self._rs2_name = rs2_name


class Players(collections.MutableSequence):
    def __init__(self, p: MutableSequence[Player] = None):
        super().__init__()
        if p is not None:
            self._players = p
        else:
            self._players = []

    def insert(self, index: int, player: Player):
        self._players[index] = player

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> Player:
        ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[Player]:
        ...

    def __getitem__(self, i: Union[int, slice]
                    ) -> Union[Player, MutableSequence[Player]]:
        return self._players[i]

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: Player):
        ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[Player]):
        ...

    def __setitem__(self, i: Union[int, slice],
                    o: Union[Player, MutableSequence[Player]]):
        self._players[i] = o

    @overload
    @abstractmethod
    def __delitem__(self, i: int):
        ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice):
        ...

    def __delitem__(self, i: Union[int, slice]):
        del self._players[i]

    def __len__(self) -> int:
        return len(self._players)


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
        return f"{self._sender} {channel}: {self._text}"

    def __repr__(self) -> str:
        return f"{__class__.__name__}({self.__str__()})"


class ChatMessages(collections.MutableSequence):
    def __init__(self, m: MutableSequence[ChatMessage] = None):
        super().__init__()
        if m is not None:
            self._messages = m
        else:
            self._messages = []

    def insert(self, index: int, message: ChatMessage):
        self._messages[index] = message

    def append(self, message: ChatMessage):
        self._messages.append(message)

    def extend(self, m: Union[ChatMessage, MutableSequence[ChatMessage]]):
        self._messages.extend(m)

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> ChatMessage:
        ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[ChatMessage]:
        ...

    def __getitem__(self, i: Union[int, slice]
                    ) -> Union[ChatMessage, MutableSequence[ChatMessage]]:
        return self._messages[i]

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: ChatMessage):
        ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[ChatMessage]):
        ...

    def __setitem__(self, i: Union[int, slice]
                    , o: Union[ChatMessage, MutableSequence[ChatMessage]]):
        self._messages[i] = o

    @overload
    @abstractmethod
    def __delitem__(self, i: int):
        ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice):
        ...

    def __delitem__(self, i: Union[int, slice]):
        del self._messages[i]

    def __len__(self) -> int:
        return len(self._messages)

    def __str__(self) -> str:
        return self._messages.__str__()


class Scoreboard(List[str]):
    pass


class CurrentGame(Model):
    def __init__(self):
        super().__init__()


class AccessPolicy(Model):
    pass
