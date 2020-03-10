from __future__ import annotations

import itertools
import sys
from typing import List
from typing import Sequence
from typing import Type
from typing import Union

from logbook import Logger
from logbook import StreamHandler

from rs2wapy.adapters import PlayerWrapper
from rs2wapy.adapters import WebAdminAdapter
from rs2wapy.models import AccessPolicy
from rs2wapy.models import AllTeam
from rs2wapy.models import ChatMessage
from rs2wapy.models import CurrentGame
from rs2wapy.models import MapCycle
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
        :param webadmin_url: RS2 WebAdmin URL.
        """
        self._adapter = WebAdminAdapter(username, password, webadmin_url)

    def get_chat_messages(self) -> Sequence[ChatMessage]:
        """Return new chat messages since last time this method
        was called and after the creation of this RS2WebAdmin instance.
        """
        return self._adapter.get_chat_messages()

    def post_chat_message(self, message: str, team: Type[Team] = AllTeam):
        """Post new chat message, visible to specific team(s).
        """
        self._adapter.post_chat_message(message, team)

    def get_current_game(self) -> CurrentGame:
        """Return object representing current game information.
        """
        return self._adapter.get_current_game()

    def change_map(self, new_map: str, url_extra: dict = None):
        """Change map. New map name is provided as a string.
        The url_extra parameter is a dictionary, with extra
        URL variables as keys and URL variable values as values.

        Example call:
        change_map("VNTE-Resort", url_extra={
          "MaxPlayers": 64,
          "mutator": "ExampleMutator",
        })

        The url_extra parameter corresponds to the WebAdmin
        'Additional URL variables' input option.
        """
        if url_extra is None:
            url_extra = {}
        self._adapter.change_map(new_map, url_extra)

    def get_maps(self) -> dict:
        """Return maps currently installed on the server.
        Return value is a dictionary with game mode names
        as keys and map name lists as values:

        Example return value:
        {
          'ROGame.ROGameInfoTerritories': ['VNTE-Resort', 'VNTE-CuChi'],
          'ROGame.ROGameInfoSupremacy': ['VNSU-Resort'],
        }
        """
        return self._adapter.get_maps()

    def get_maps_list(self) -> List[str]:
        """Return list of all maps of all game modes
        currently installed on the server.
        """
        return list(
            itertools.chain(*self._adapter.get_maps().values())
        )

    def get_players(self) -> List[PlayerWrapper]:
        """Return players currently online on the server.
        Return value is a list of adapters.PlayerWrapper objects
        representing the players on the server at the time of
        the invocation of this method.
        """
        return self._adapter.get_players()

    def get_player_scoreboard(self) -> PlayerScoreboard:
        """Return current player scoreboard. Player scoreboard
        does not store player IDs, because deducing them
        from WebAdmin is unreliable.
        """
        return self._adapter.get_current_game().player_scoreboard

    def get_team_scoreboard(self) -> TeamScoreboard:
        """Return current team scoreboard.
        """
        return self._adapter.get_current_game().team_scoreboard

    def get_squads(self):
        raise NotImplementedError

    def get_banned_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_banned_players()

    def get_tracked_players(self) -> dict:
        raise NotImplementedError
        # return self._adapter.get_tracked_players()

    def get_access_policies(self) -> List[AccessPolicy]:
        raise NotImplementedError
        # return self._adapter.get_access_policies()

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

    def get_map_cycles(self) -> List[MapCycle]:
        return self._adapter.get_map_cycles()

    def set_map_cycles(self, map_cycles: List[MapCycle]):
        self._adapter.set_map_cycles(map_cycles)

    def get_advertisement_messages(self) -> List[str]:
        raise NotImplementedError

    def set_advertisement_messages(self, ad_msgs: List[str]):
        raise NotImplementedError

    def get_advertisement_interval(self) -> int:
        raise NotImplementedError

    def set_advertisement_interval(self, ad_interval: int):
        raise NotImplementedError
