import abc
import collections
import datetime
from abc import abstractmethod
from typing import Iterable
from typing import MutableSequence
from typing import Union
from typing import overload

from steam import SteamID


class Model(abc.ABC):
    def __init__(self):
        self._timestamp = datetime.datetime.now()

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: datetime.datetime):
        self._timestamp = timestamp


_STEAM_ID_TYPE = Union[SteamID, int, str]


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

    def insert(self, index: int, player: Player) -> None:
        self._players[index] = player

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> Player:
        ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[Player]:
        ...

    def __getitem__(self, i: Union[int, slice]) -> Union[Player, MutableSequence[Player]]:
        return self._players[i]

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: Player) -> None:
        ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[Player]) -> None:
        ...

    def __setitem__(self, i: int, o: Player) -> None:
        pass

    @overload
    @abstractmethod
    def __delitem__(self, i: int) -> None:
        ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice) -> None:
        ...

    def __delitem__(self, i: int) -> None:
        pass

    def __len__(self) -> int:
        return len(self._players)


class ChatMessage(Model):
    def __init__(self, sender: Player, text: str):
        super().__init__()
        self._sender = sender
        self._text = text


class ChatMessages(collections.MutableSequence):
    def __init__(self, m: MutableSequence[ChatMessage] = None):
        super().__init__()
        if m is not None:
            self._messages = m
        else:
            self._messages = []

    def insert(self, index: int, message: ChatMessage):
        self._messages[index] = message

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> ChatMessage:
        ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[ChatMessage]:
        ...

    def __getitem__(self, i: Union[int, slice]) -> Union[ChatMessage, MutableSequence[ChatMessage]]:
        return self._messages[i]

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: ChatMessage):
        ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[ChatMessage]):
        ...

    def __setitem__(self, i: int, o: ChatMessage):
        pass

    @overload
    @abstractmethod
    def __delitem__(self, i: int):
        ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice):
        ...

    def __delitem__(self, i: int):
        pass

    def __len__(self) -> int:
        return len(self._messages)


class Chat(Model):

    def __init__(self):
        super().__init__()

    def get_messages(self) -> ChatMessages:
        # Get messages via adapter.
        pass

    def post_message(self):
        # Post message via adapter.
        pass


class CurrentGame(Model):
    def __init__(self):
        super().__init__()

    def get_players(self) -> Players:
        pass
