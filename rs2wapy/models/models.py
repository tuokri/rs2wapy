import abc
import collections
import datetime
from abc import abstractmethod
from typing import Iterable
from typing import MutableSequence
from typing import _T
from typing import overload


class Model(abc.ABC):
    def __init__(self):
        self._timestamp = datetime.datetime.now()

    @property
    def timestamp(self) -> datetime.datetime:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp: datetime.datetime):
        self._timestamp = timestamp


class Player(Model):
    def __init__(self):
        super().__init__()


class Players(Model, collections.MutableSequence):
    def __init__(self):
        super().__init__()

    def insert(self, index: int, object: _T) -> None:
        pass

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> _T: ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[_T]: ...

    def __getitem__(self, i: int) -> _T:
        pass

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: _T) -> None: ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[_T]) -> None: ...

    def __setitem__(self, i: int, o: _T) -> None:
        pass

    @overload
    @abstractmethod
    def __delitem__(self, i: int) -> None: ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice) -> None: ...

    def __delitem__(self, i: int) -> None:
        pass

    def __len__(self) -> int:
        pass


class ChatMessage(Model):
    def __init__(self, sender: Player, text: str):
        super().__init__()
        self._sender = sender
        self._text = text


class ChatMessages(Model, collections.MutableSequence):
    def __init__(self):
        super().__init__()
        self._messages = []

    def insert(self, index: int, message: ChatMessage):
        self._messages[index] = message

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> ChatMessage: ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> MutableSequence[ChatMessage]: ...

    def __getitem__(self, i: int) -> ChatMessage:
        return self._messages[i]

    @overload
    @abstractmethod
    def __setitem__(self, i: int, o: ChatMessage): ...

    @overload
    @abstractmethod
    def __setitem__(self, s: slice, o: Iterable[ChatMessage]): ...

    def __setitem__(self, i: int, o: ChatMessage):
        pass

    @overload
    @abstractmethod
    def __delitem__(self, i: int): ...

    @overload
    @abstractmethod
    def __delitem__(self, i: slice): ...

    def __delitem__(self, i: int):
        pass

    def __len__(self) -> int:
        return len(self._messages)


class Chat(Model):

    def __init__(self):
        super().__init__()

    def get_messages(self) -> ChatMessages:
        pass

    def post_message(self):
        pass


class CurrentGame(Model):
    def __init__(self):
        super().__init__()

    def get_players(self) -> Players:
        pass
