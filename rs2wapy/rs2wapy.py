import sys

from logbook import Logger
from logbook import StreamHandler

from .adapter import Adapter
from .models import models

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)


class RS2WebAdmin(object):
    """

    """

    def __init__(self, username: str, password: str, webadmin_url: str):
        self._adapter = Adapter(username, password, webadmin_url)

    def chat(self) -> models.Chat:
        return self._adapter.get_chat()

    def chat_messages(self) -> models.ChatMessages:
        return self.chat().get_messages()

    def current_game(self) -> models.CurrentGame:
        return self._adapter.get_current_game()

    def current_players(self) -> models.Players:
        return self.current_game().get_players()

    def banned_players(self) -> models.Players:
        return self.current_game().get_banned_players()

    def tracked_players(self) -> models.Players:
        return self.current_game().get_tracked_players()

    def access_policy(self) -> models.AccessPolicy:
        return self._adapter.get_access_policy()
