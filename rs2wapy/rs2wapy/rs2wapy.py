# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""High-level API."""

from __future__ import annotations

from typing import Type

from rs2wapy.adapters import PlayerWrapper
from rs2wapy.adapters import WebAdminAdapter
from rs2wapy.adapters.adapters import BanWrapper
from rs2wapy.adapters.adapters import MemberWrapper
from rs2wapy.adapters.adapters import SessionBanWrapper
from rs2wapy.adapters.adapters import SquadWrapper
from rs2wapy.adapters.adapters import TrackingWrapper
from rs2wapy.models import AccessPolicy
from rs2wapy.models import AllTeam
from rs2wapy.models import ChatMessage
from rs2wapy.models import CurrentGame
from rs2wapy.models import MapCycle
from rs2wapy.models import Player
from rs2wapy.models import PlayerScoreboard
from rs2wapy.models import Team
from rs2wapy.models import TeamScoreboard


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

    async def get_chat_messages(self) -> list[ChatMessage]:
        """Return new chat messages since the last time this method
        was called and after the creation of this RS2WebAdmin instance.
        """
        return await self._adapter.get_chat_messages()

    async def post_chat_message(self, message: str, team: Type[Team] = AllTeam):
        """Post a new chat message, visible to specific team(s).

        :param message:
            The chat message to post.
        :param team:
            The team the message is visible to.
        """
        await self._adapter.post_chat_message(message, team)

    async def get_current_game(self) -> CurrentGame:
        """Return the object representing current game information."""
        return await self._adapter.get_current_game()

    async def change_map(self, new_map: str, url_extra: dict | None = None):
        """Change map.

        :param new_map:
            New map name string.
        :param url_extra:
            Dictionary, with extra URL variables as keys
            and URL variable values as values.

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
        await self._adapter.change_map(new_map, url_extra)

    async def get_maps(self) -> dict[str, list[str]]:
        """Return maps currently installed on the server.
        Return value is a dictionary with game mode names
        as keys and map name lists as values:

        Example return value:
        {
          'ROGame.ROGameInfoTerritories': ['VNTE-Resort', 'VNTE-CuChi'],
          'ROGame.ROGameInfoSupremacy': ['VNSU-Resort'],
        }
        """
        return await self._adapter.get_maps()

    async def get_maps_list(self) -> list[str]:
        """Return the list of all maps of all game modes
        currently installed on the server.
        """
        return await self._adapter.get_maps_list()

    async def get_players(self) -> list[PlayerWrapper]:
        """Return players currently online on the server.
        Return value is a list of adapters.PlayerWrapper objects
        representing the players on the server at the time of
        the invocation of this method.
        """
        return await self._adapter.get_players()

    async def get_player_scoreboard(self) -> PlayerScoreboard:
        """Return the current player scoreboard. Player scoreboard
        does not store player IDs because deducing them
        from WebAdmin is unreliable.
        """
        return (await self._adapter.get_current_game()).player_scoreboard

    async def get_team_scoreboard(self) -> TeamScoreboard:
        """Return the current team scoreboard."""
        return (await self._adapter.get_current_game()).team_scoreboard

    async def get_squads(self) -> list[SquadWrapper]:
        """Return current squads."""
        return await self._adapter.get_squads()

    async def get_banned_players(self) -> list[BanWrapper]:
        """Return banned players."""
        return await self._adapter.get_banned_players()

    async def get_session_banned_players(self) -> list[SessionBanWrapper]:
        """Return session banned players."""
        return await self._adapter.get_session_banned_players()

    async def get_tracked_players(self) -> list[TrackingWrapper]:
        """Return tracked players.

        WARNING: This method is extremely slow for servers
        with large tracking databases.

        TODO: Can we leverage asyncio?
        TODO: Background collection like chat?
        """
        return await self._adapter.get_tracked_players()

    async def get_access_policies(self) -> list[AccessPolicy]:
        """Return access policies."""
        raise NotImplementedError
        # return self._adapter.get_access_policies()

    async def add_access_policy(self, ip_mask: str, policy: str):
        raise NotImplementedError
        # self._adapter.add_access_policy(ip_mask, policy)

    async def ban_player(
        self,
        player: Player | PlayerWrapper,
        reason: str,
        duration: str | None = None,
        notify_players: bool = False,
    ):
        # TODO: Use correct notation when referring to
        #  "external" variables in the docstring.
        """Ban player from the server.

        :param player:
            The player to ban.
        :param reason:
            Ban reason.
        :param duration:
            Duration string. Ban is permanent if no
            duration string is supplied.

            If the string is ill-formed,
            the ban will be interpreted as permanent.

            The expected format is '{length}{ws}{unit}',
            where {length} is a positive integer, {ws}
            is an optional whitespace and {unit} is one of
            `rs2wapy.adapters.BAN_EXP_UNITS`. The string is
            case-insensitive.

            Example duration strings:
            '4 Hour'
            '3day'
            '1Year'
        :param notify_players:
            If True, notify players on the server.
        """
        await self._adapter.ban_player(
            player, reason=reason, duration=duration, notify_players=notify_players
        )

    async def kick_player(
        self,
        player: Player | PlayerWrapper,
        reason: str,
        notify_players: bool = False,
    ):
        """Kick player from the server.

        :param player:
            The player to kick.
        :param reason:
            Kick reason.
        :param notify_players:
            If True, notify players on the server.
        """
        await self._adapter.kick_player(player, reason, notify_players)

    async def session_ban_player(
        self,
        player: Player | PlayerWrapper,
        reason: str,
        notify_players: bool = False,
    ):
        """Session ban player from the server.
        Session bans reset when the server changes level.

        :param player:
            The player to session ban.
        :param reason:
            Session ban reason.
        :param notify_players:
            If True, notify players on the server.
        """
        await self._adapter.session_ban_player(player, reason, notify_players)

    async def get_map_cycles(self) -> list[MapCycle]:
        """Return map cycles."""
        return await self._adapter.get_map_cycles()

    async def set_map_cycles(self, map_cycles: list[MapCycle]):
        """Set map cycles."""
        await self._adapter.set_map_cycles(map_cycles)

    async def get_advertisement_messages(self) -> list[str]:
        raise NotImplementedError

    async def set_advertisement_messages(self, ad_msgs: list[str]):
        raise NotImplementedError

    async def get_advertisement_interval(self) -> int:
        raise NotImplementedError

    async def set_advertisement_interval(self, ad_interval: int):
        raise NotImplementedError

    async def get_members(self) -> list[MemberWrapper]:
        return await self._adapter.get_members()
