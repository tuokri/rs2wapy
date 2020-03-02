import sys
from typing import Type

from logbook import Logger
from logbook import StreamHandler

from .adapter import Adapter
from .models import models

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)


class RS2WebAdmin(object):
    """
    Provides a high-level interface to Rising Storm 2: Vietnam
    server's WebAdmin tool.
    """

    def __init__(self, username: str, password: str, webadmin_url: str):
        self._adapter = Adapter(username, password, webadmin_url)

    def get_chat_messages(self) -> models.ChatMessages:
        return self._adapter.get_chat_messages()

    def post_chat_message(self, message: str, team: Type[models.Team]):
        self._adapter.post_chat_message(message, team)

    def get_current_game(self) -> models.CurrentGame:
        return self._adapter.get_current_game()

    def change_map(self, new_map: str):
        self._adapter.change_map(new_map)

    def get_maps(self):
        return self._adapter.get_maps()

    def get_players(self) -> models.Players:
        return self._adapter.get_players()

    def get_scoreboard(self) -> models.Scoreboard:
        return self._adapter.get_current_game().player_scoreboard

    # TODO: Banned players dict-like object, with ban info as value.
    def get_banned_players(self) -> models.Players:
        return self._adapter.get_banned_players()

    # TODO: Tracked players dict-like object, with tracking info as value.
    def get_tracked_players(self) -> models.Players:
        return self._adapter.get_tracked_players()

    def get_access_policy(self) -> models.AccessPolicy:
        return self._adapter.get_access_policy()

    def add_access_policy(self, ip_mask: str, policy: str):
        self._adapter.add_access_policy(ip_mask, policy)
