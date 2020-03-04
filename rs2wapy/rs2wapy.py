import sys
from typing import Sequence
from typing import Type
from typing import Union

from logbook import Logger
from logbook import StreamHandler

from rs2wapy.adapters import WebAdminAdapter
from rs2wapy.adapters import PlayerWrapper
from rs2wapy.models import AccessPolicy
from rs2wapy.models import ChatMessage
from rs2wapy.models import CurrentGame
from rs2wapy.models import Player
from rs2wapy.models import PlayerScoreboard
from rs2wapy.models import Team
from rs2wapy.models import TeamScoreboard

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
        self._adapter = WebAdminAdapter(username, password, webadmin_url)

    def get_chat_messages(self) -> Sequence[ChatMessage]:
        """Return new chat messages since last time this method was called.
        TODO: Clarify this doc.
        See issue #4.
        """
        return self._adapter.get_chat_messages()

    def post_chat_message(self, message: str, team: Type[Team]):
        """Post new chat message, visible to specific team(s).
        """
        self._adapter.post_chat_message(message, team)

    def get_current_game(self) -> CurrentGame:
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

    def get_player_scoreboard(self) -> PlayerScoreboard:
        """Return current player scoreboard.
        """
        return self._adapter.get_current_game().player_scoreboard

    def get_team_scoreboard(self) -> TeamScoreboard:
        """Return current team scoreboard.
        """
        return self._adapter.get_current_game().team_scoreboard

    def get_banned_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_banned_players()

    def get_tracked_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_tracked_players()

    def get_access_policy(self) -> AccessPolicy:
        raise NotImplementedError
        # return self._adapter.get_access_policy()

    def add_access_policy(self, ip_mask: str, policy: str):
        raise NotImplementedError
        # self._adapter.add_access_policy(ip_mask, policy)

    def ban_player(self, player: Union[Player, PlayerWrapper],
                   reason: str, duration: str):
        self._adapter.ban_player(player, reason, duration)

    def kick_player(self, player: Union[Player, PlayerWrapper],
                    reason: str, duration: str):
        self._adapter.kick_player(player, reason, duration)

    def session_ban_player(self, player: Union[Player, PlayerWrapper],
                           reason: str):
        self._adapter.session_ban_player(player, reason)
