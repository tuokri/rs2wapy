import sys
from typing import Sequence
from typing import Type

from logbook import Logger
from logbook import StreamHandler

from .adapters import Adapter
from .models import models

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)


class RS2WebAdmin:
    """Provides a high-level interface to Rising Storm 2: Vietnam
    server's WebAdmin tool.
    """

    def __init__(self, username: str, password: str, webadmin_url: str):
        """
        :param username: RS2 WebAdmin username.
        :param password: RS2 WebAdmin password.
        :param webadmin_url: RS2 WebAdmin url.
        """
        self._adapter = Adapter(username, password, webadmin_url)

    def get_chat_messages(self) -> Sequence[models.ChatMessage]:
        """Return new chat messages since last time this method was called.
        TODO: Clarify this doc.
        """
        return self._adapter.get_chat_messages()

    def post_chat_message(self, message: str, team: Type[models.Team]):
        """Post new chat message, visible to specific team(s).
        """
        self._adapter.post_chat_message(message, team)

    def get_current_game(self) -> models.CurrentGame:
        """Return object representing current game information.
        """
        return self._adapter.get_current_game()

    def change_map(self, new_map: str, url_extra: dict = None):
        if url_extra is None:
            url_extra = {}
        self._adapter.change_map(new_map, url_extra)

    def get_maps(self) -> dict:
        """Return maps currently installed on the server.
        """
        return self._adapter.get_maps()

    def get_players(self) -> dict:
        """Return players currently online on the server.
        """
        return self._adapter.get_players()

    def get_player_scoreboard(self) -> models.PlayerScoreboard:
        """Return current player scoreboard.
        """
        return self._adapter.get_current_game().player_scoreboard

    def get_team_scoreboard(self) -> models.TeamScoreboard:
        """Return current team scoreboard.
        """
        return self._adapter.get_current_game().team_scoreboard

    def get_banned_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_banned_players()

    def get_tracked_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_tracked_players()

    def get_access_policy(self) -> models.AccessPolicy:
        raise NotImplementedError
        # return self._adapter.get_access_policy()

    def add_access_policy(self, ip_mask: str, policy: str):
        raise NotImplementedError
        # self._adapter.add_access_policy(ip_mask, policy)

    def ban_player(self, player: models.Player, reason, duration):
        raise NotImplementedError

    def kick_player(self, player: models.Player, reason, duration):
        raise NotImplementedError

    def session_ban_player(self, player: models.Player, reason):
        raise NotImplementedError
