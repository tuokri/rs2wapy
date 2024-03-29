"""
Provides utilities for parsing responses from
Rising Storm 2: Vietnam WebAdmin.

TODO: This module is growing fast. Needs refactoring.
"""
from __future__ import annotations

import re
import sys
from functools import lru_cache
from typing import Dict
from typing import List
from typing import Sequence
from typing import Tuple
from typing import Union

from bs4 import BeautifulSoup
from logbook import Logger
from logbook import StreamHandler
from steam.steamid import SteamID

import rs2wapy.models as models
from rs2wapy.adapters import adapters
from rs2wapy.epicgamesstore import EGSID
from rs2wapy.steam import SteamWebAPI

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)

TEAMCOLOR_PATTERN = re.compile(r"background: (.*);")
ROUND_LIMIT_SUB_PATTERN = re.compile(r"\?RoundLimit=([0-9]*)")
ROUND_LIMIT_MATCH_PATTERN = re.compile(r".*\?RoundLimit=([0-9]*).*")
NO_PLAYERS = ["There are no players"]
UNIQUE_ID_KEY = "Unique ID"
TEAM_INDEX_KEY = "\xa0"


class RS2WebAdminResponseParser:
    # TODO: Refactor magic numbers.

    def __init__(self, encoding: str = None):
        if not encoding:
            encoding = "iso-8859-1"
        self._encoding = encoding

    def parse_html(self, resp: bytes, encoding: str = None) -> BeautifulSoup:
        if not encoding:
            encoding = self._encoding
        return BeautifulSoup(resp.decode(encoding), features="html.parser")

    def parse_chat_messages(self, resp: bytes,
                            encoding: str = None) -> Sequence[models.ChatMessage]:
        parsed_html = self.parse_html(resp, encoding)
        chat_message_divs = parsed_html.find_all(
            "div", attrs={"class": "chatmessage"})
        # parsed_html.find_all("div", attrs={"class": "chatnotice"})
        cm = []
        for div in chat_message_divs:
            cm.append(self.parse_chat_message(div))
        return cm

    def parse_access_policy(self, resp: bytes,
                            encoding: str = None) -> List[str]:
        parsed_html = self.parse_html(resp, encoding)
        policy_table = parsed_html.find("table", attrs={"id": "policies"})
        trs = policy_table.find_all("tr")
        policies = []
        for tr in trs:
            ip_mask = tr.find("input", attrs={"name": "ipmask"})
            policy = tr.find("option", attrs={"selected": "selected"})
            if ip_mask and policy:
                policies.append(
                    f"{ip_mask.get('value')}: {policy.text.upper()}")
        return policies

    def parse_current_game(self, resp: bytes) -> models.CurrentGame:
        """TODO: headers vs. rows length assertion!"""
        parsed_html = self.parse_html(resp)

        info = {}
        rules = {}
        p_scores = {}
        t_scores = {}

        logger.info("parsing Ranked status")
        ranked = parsed_html.find(
            "span", attrs={"class": "ranked"}).text
        ranked = True if ranked.lower() == "ranked: yes" else False
        info["Ranked"] = ranked

        logger.info("parsing player scoreboard")
        player_scoreboard_table = parsed_html.find(
            "table", attrs={"id": "players"})
        player_scoreboard_thead = player_scoreboard_table.find("thead")
        p_thead = player_scoreboard_thead.find_all(
            "a", attrs={"class": "sortable"})
        p_headers = ["Team"]
        p_headers.extend([h.text.strip() for h in p_thead])
        p_headers.extend(["Admin", "Spectator"])

        p_row_elements = player_scoreboard_table.find_all("tr")
        p_scoreboard_parsed = self._parse_table(p_row_elements)
        for p_cols in p_scoreboard_parsed:
            p_cols[0] = "North" if p_cols[0] == "0" else "South"
            for p_key, p_col in zip(p_headers, p_cols):
                p_scores[p_key] = p_col
        player_scoreboard = models.PlayerScoreboard(stats=p_scores)

        logger.info("parsing team scoreboard")
        team_scoreboard_table = parsed_html.find(
            "table", attrs={"id": "teams"})
        t_thead = team_scoreboard_table.find("thead")
        t_headers = t_thead.find_all("th")
        t_headers = [h.text.strip() for h in t_headers]
        t_headers = ["Team Index"] + t_headers[1:]

        t_row_elements = team_scoreboard_table.find_all("tr")
        t_scoreboard_parsed = self._parse_table(t_row_elements)
        for t_cols in t_scoreboard_parsed:
            for t_key, t_col in zip(t_headers, t_cols):
                t_scores[t_key] = t_col

        team_scoreboard = models.TeamScoreboard(stats=t_scores)

        logger.info("parsing currentGame and currentRules")
        info_element = parsed_html.find("dl", attrs={"id": "currentGame"})
        rules_element = parsed_html.find("dl", attrs={"id": "currentRules"})

        info_dts = info_element.find_all("dt")
        info_dds = info_element.find_all("dd")
        rules_dts = rules_element.find_all("dt")
        rules_dds = rules_element.find_all("dd")

        len_info_dts = len(info_dts)
        len_info_dds = len(info_dds)
        len_rules_dts = len(rules_dts)
        len_rules_dds = len(rules_dds)

        logger.debug(
            "found {lidts} info_dts, {lidds} info_dds, "
            "{lrtss} rules_dts, {lrdds} rules_dds",
            lidts=len_info_dts,
            lidds=len_info_dds,
            lrtss=len_rules_dts,
            lrdds=len_rules_dds,
        )

        if len_info_dts != len_info_dds:
            logger.warning(
                "possible missing info data: len_info_dts({lidts}) "
                "!= len_info_dds({lidds})",
                lidts=len_info_dts, lidds=len_info_dds,
            )

        if len_info_dts != len_info_dds:
            logger.warning(
                "possible missing rules data: len_rules_dts({lrdts}) "
                "!= len_rules_dds({lrdds})",
                lrdts=len_rules_dts, lrdds=len_rules_dds,
            )

        logger.info("parsing Map and Game Type")
        # Get "Map" and "Game Type", which contain
        # <code> tag in their text.
        code_elements = []
        for idt, idd in zip(info_dts, info_dds):
            code_el = idd.find("code")
            if code_el:
                code_elements.append((idt, idd.find("code").text))
                idt.extract()
                idd.extract()
        for cd in code_elements:
            info[cd[0].text] = cd[1]

        # Find again after extracting some
        # elements to avoid duplicating them.
        info_dts = info_element.find_all("dt")
        info_dds = info_element.find_all("dd")

        for idt, idd in zip(info_dts, info_dds):
            info[idt.text] = idd.text
        for rdt, rdd in zip(rules_dts, rules_dds):
            rules[rdt.text] = rdd.text

        time_limit = rules["Time Limit"]
        limit, remaining, remainder = time_limit.split("seconds")
        limit = f"{limit.strip()} seconds"
        remaining = f"{remaining.strip()} seconds"
        rules["Time Limit"] = f"{limit} ({remaining} {remainder.strip()})"

        cmpgn_active = info["MP Campaign Active"]
        info["MP Campaign Active"] = (
            True if cmpgn_active.startswith("Yes") else False)

        info["Server Name"] = info["Server Name"].split("\r")[0]

        return models.CurrentGame(
            player_scoreboard=player_scoreboard,
            team_scoreboard=team_scoreboard,
            info=info,
            rules=rules,
        )

    def parse_mutator_group_count(self, resp: bytes) -> int:
        parsed_html = self.parse_html(resp)
        mutator_group_count = int(parsed_html.find(
            "input", attrs={"name": "mutatorGroupCount"}).get("value"))
        return mutator_group_count

    def parse_game_type_options(self, resp: bytes) -> List[str]:
        parsed_html = self.parse_html(resp)
        options = parsed_html.find(
            "select", attrs={"id": "gametype"}).find_all("option")
        return [o.get("value").strip() for o in options]

    def parse_map_options(self, resp: bytes) -> List[str]:
        parsed_html = self.parse_html(resp)
        options = parsed_html.find(
            "select", attrs={"id": "map"}).find_all("option")
        return [o.get("value").strip() for o in options]

    def parse_players(self, resp: bytes, adapter: adapters.WebAdminAdapter
                      ) -> List[adapters.PlayerWrapper]:
        parsed_html = self.parse_html(resp)
        if not parsed_html:
            logger.error(
                "unable to parse players; no response"
                " data to parse")
            return []

        player_table = parsed_html.find("table", attrs={"id": "players"})

        player_headers = player_table.find("thead")
        player_headers = player_headers.find_all("th")

        player_table = player_table.find("tbody")
        player_table = player_table.find_all("tr")
        player_table = self._parse_table(player_table)

        # Not expecting this header to ever change order.
        # We could probably hard-code this...
        player_headers = [ph.text for ph in player_headers]
        player_headers[player_headers.index(TEAM_INDEX_KEY)] = "Team Index"

        if (len(player_table) == 1) and player_table[0] == NO_PLAYERS:
            logger.debug("no players")
            return []

        if not all(len(p) for p in player_table):
            logger.error(
                "player rows in player table differ in length")
            return []

        if not len(player_table[0]) == len(player_headers):
            logger.error("player table and player headers differ in length")
            return []

        # We use 'Unique ID' column here instead of 'Steam ID'
        # column because 'Steam ID' column is sometimes not filled.
        # 'Unique ID' is just a hex-string of the user's SteamID64
        # anyway. EGS players are also handled in similar way.
        id_index = player_headers.index(UNIQUE_ID_KEY)

        players = []
        id_to_stats: Dict[Union[SteamID, EGSID], Dict] = {}
        steam_ids = []
        egs_ids = []

        for player_row in player_table:
            unique_id = player_row[id_index]

            try:
                int_id = int(unique_id, 16)
                is_steam_id = self._is_steam_id(int_id)
            except ValueError as ve:
                logger.exception(ve)
                logger.error("invalid Unique ID: '{uid}', skipping", uid=unique_id)
                continue

            stats = {
                key: value for key, value in zip(
                    player_headers, player_row)
                if key.lower() != "actions"
            }

            if is_steam_id:
                steam_id = SteamID(int_id)
                steam_ids.append(steam_id)
                id_to_stats[steam_id] = stats
            else:
                egs_id = EGSID(int_id)
                egs_ids.append(egs_id)
                id_to_stats[egs_id] = stats

        persona_names = SteamWebAPI().get_persona_names(
            steam_ids=steam_ids
        )

        for steam_id in steam_ids:
            persona_name = ""
            try:
                persona_name = persona_names[steam_id]
            except KeyError as ke:
                logger.error(
                    "error getting persona name for Steam ID: {sid}",
                    sid=steam_id)
                logger.exception(ke)

            p_stats = id_to_stats[steam_id]
            player = models.Player(ident=steam_id, stats=p_stats, persona_name=persona_name)

            players.append(adapters.PlayerWrapper(
                player=player,
                adapter=adapter,
            ))

        for egs_id in egs_ids:
            p_stats = id_to_stats[egs_id]

            player = models.Player(ident=egs_id, stats=p_stats)

            players.append(adapters.PlayerWrapper(
                player=player,
                adapter=adapter,
            ))

        return players

    def parse_hash_alg(self, resp: bytes) -> str:
        parsed_html = self.parse_html(resp)
        login_script = parsed_html.find("script", text=re.compile(r".*hashAlg.*"))
        match = re.search(r'.*var\shashAlg\s=\s"(.*)";.*', str(login_script))
        alg = ""
        if match:
            alg = match.group(1)
        return alg

    def parse_map_list_indices(self, resp) -> dict:
        parsed_html = self.parse_html(resp)
        map_list_idxs = parsed_html.find(
            "select", attrs={"id": "maplistidx"})
        map_list_idxs = map_list_idxs.find_all("option")

        valid_idxs = {}
        for mli in map_list_idxs:
            try:
                idx = int(mli.get("value"))
                if idx >= 0:
                    is_active = "active" in mli.text.lower()
                    valid_idxs[idx] = is_active
            except ValueError as ve:
                logger.warning("{ve} during map list index conversion to int",
                               ve=ve)

        return valid_idxs

    def parse_map_cycle(self, resp) -> List[Tuple[str, int]]:
        """
        Return list of tuples (map name, round limit).
        """
        parsed_html = self.parse_html(resp)
        maps = parsed_html.find(
            "textarea", attrs={"id": "mapcycle"}
        ).text
        maps = maps.split("\n")

        round_limits = []
        for m in maps:
            rl = re.match(ROUND_LIMIT_MATCH_PATTERN, m)
            if rl:
                round_limits.append(int(rl.group(1)))
            else:
                round_limits.append(0)

        if len(round_limits) != len(maps):
            logger.error("round limit list and map list length mismatch")

        maps = [(re.sub(ROUND_LIMIT_SUB_PATTERN, "", m), rl)
                for m, rl in zip(maps, round_limits)]
        return maps

    def parse_squads(self, resp: bytes,
                     adapter: adapters.WebAdminAdapter
                     ) -> List[adapters.SquadWrapper]:
        parsed_html = self.parse_html(resp)
        parsed_html = parsed_html.find("table", attrs={"id": "squads"})

        squads_table = parsed_html.find("tbody")
        squads_table = squads_table.find_all("tr")
        squads_table = self._parse_table(squads_table)

        squads = []
        for row in squads_table:
            try:
                team_idx = int(row[0].strip())
                team = models.Team.from_team_index(team_idx)
            except Exception as e:
                team = models.UnknownTeam
                logger.error("unable to parse squad team: {e}", e=e)

            number = -1
            try:
                number = int(row[1])
            except Exception as e:
                logger.error("unable to parse squad number: {e}", e=e)

            name = ""
            try:
                name = row[2]
            except Exception as e:
                logger.error("unable to parse squad name: {e}", e=e)

            squads.append(models.Squad(
                team=team,
                number=number,
                name=name,
            ))

        squad_wrappers = [
            adapters.SquadWrapper(
                squad=squad,
                adapter=adapter,
            ) for squad in squads
        ]

        return squad_wrappers

    def parse_tracking(self, resp: bytes,
                       adapter: adapters.WebAdminAdapter
                       ) -> List[adapters.TrackingWrapper]:

        parsed_html = self.parse_html(resp)
        tracking_table = parsed_html.find("table", attrs={"id": "tracking"})
        tracking_headers = [th.text for th in tracking_table.find_all("th")]
        tracking_tbody = tracking_table.find("tbody")
        tb_row_entries = tracking_tbody.find_all("tr")
        tracking_rows = self._parse_table(tb_row_entries)

        # Unique ID field is more reliable as Steam ID
        # might be missing in the table in some cases.
        id_index = tracking_headers.index(UNIQUE_ID_KEY)

        id_to_tracking_data = {}
        steam_ids = []
        egs_ids = []

        for row in tracking_rows:
            unique_id = row[id_index]

            try:
                int_id = int(unique_id, 16)
                is_steam_id = self._is_steam_id(int_id)
            except ValueError as ve:
                logger.exception(ve)
                logger.error("invalid Unique ID: '{uid}', skipping", uid=unique_id)
                continue

            tracking_data = {
                key: value for key, value in zip(
                    tracking_headers, row)
                if key.lower() != "actions"
            }

            if is_steam_id:
                steam_id = SteamID(int_id)
                steam_ids.append(steam_id)
                id_to_tracking_data[steam_id] = tracking_data
            else:
                egs_id = EGSID(int_id)
                egs_ids.append(egs_id)
                id_to_tracking_data[egs_id] = tracking_data

        persona_names = SteamWebAPI().get_persona_names(
            steam_ids=steam_ids
        )

        tracking_wrappers = []

        for steam_id in steam_ids:
            persona_name = ""
            try:
                persona_name = persona_names[steam_id]
            except KeyError as ke:
                logger.error(
                    "error getting persona name for Steam ID: {sid}",
                    sid=steam_id)
                logger.exception(ke)

            tracking_data = id_to_tracking_data[steam_id]
            player = models.Player(ident=steam_id, persona_name=persona_name)

            tracking_wrappers.append(adapters.TrackingWrapper(
                player=player,
                tracking_data=tracking_data,
                adapter=adapter,
            ))

        for egs_id in egs_ids:
            tracking_data = id_to_tracking_data[egs_id]

            player = models.Player(ident=egs_id)

            tracking_wrappers.append(adapters.TrackingWrapper(
                player=player,
                tracking_data=tracking_data,
                adapter=adapter,
            ))

        return tracking_wrappers

    def parse_bans(self, resp: bytes,
                   adapter: adapters.WebAdminAdapter
                   ) -> List[adapters.BanWrapper]:

        parsed_html = self.parse_html(resp)
        ban_table = parsed_html.find("table", attrs={"class": "grid"})
        ban_headers = [th.text for th in ban_table.find_all("th")]
        ban_tbody = ban_table.find("tbody")
        ban_row_entries = ban_tbody.find_all("tr")
        ban_rows = self._parse_table(ban_row_entries)

        if len(ban_rows) == 1:
            try:
                if ban_rows[0][0].lower() == "there are no active bans":
                    return []
            except IndexError:
                pass

        # Unique ID field is more reliable as Steam ID
        # might be missing in the table in some cases.
        id_index = ban_headers.index(UNIQUE_ID_KEY)

        id_to_extra_data = {}
        steam_ids = []
        egs_ids = []

        for row in ban_rows:
            unique_id = row[id_index]

            try:
                int_id = int(unique_id, 16)
                is_steam_id = self._is_steam_id(int_id)
            except ValueError as ve:
                logger.exception(ve)
                logger.error("invalid Unique ID: '{uid}', skipping", uid=unique_id)
                continue

            extra_data = {
                key: value for key, value in zip(
                    ban_headers, row)
                if key.lower() != "actions"
            }

            if is_steam_id:
                steam_id = SteamID(int_id)
                steam_ids.append(steam_id)
                id_to_extra_data[steam_id] = extra_data
            else:
                egs_id = EGSID(int_id)
                egs_ids.append(egs_id)
                id_to_extra_data[egs_id] = extra_data

        persona_names = SteamWebAPI().get_persona_names(
            steam_ids=steam_ids
        )

        ban_wrappers = []

        for steam_id in steam_ids:
            persona_name = ""
            try:
                persona_name = persona_names[steam_id]
            except KeyError as ke:
                logger.error(
                    "error getting persona name for Steam ID: {sid}",
                    sid=steam_id)
                logger.exception(ke)

            extra_data = id_to_extra_data[steam_id]
            player_stats = {"Player Name": extra_data["Player Name"]}
            player = models.Player(ident=steam_id, persona_name=persona_name,
                                   stats=player_stats)

            ban = models.Ban(
                player=player,
                reason=extra_data["Reason"],
                until=extra_data["Expires On"],
                admin=extra_data["Admin"],
                when=extra_data["When"],
            )

            ban_wrappers.append(adapters.BanWrapper(
                ban=ban,
                adapter=adapter,
            ))

        for egs_id in egs_ids:
            extra_data = id_to_extra_data[egs_id]

            player_stats = {"Player Name": extra_data["Player Name"]}
            player = models.Player(ident=egs_id, stats=player_stats)

            ban = models.Ban(
                player=player,
                reason=extra_data["Reason"],
                until=extra_data["Expires On"],
                admin=extra_data["Admin"],
                when=extra_data["When"],
            )

            ban_wrappers.append(adapters.BanWrapper(
                ban=ban,
                adapter=adapter,
            ))

        return ban_wrappers

    def parse_session_bans(self, resp: bytes,
                           adapter: adapters.WebAdminAdapter
                           ) -> List[adapters.SessionBanWrapper]:

        parsed_html = self.parse_html(resp)
        ban_table = parsed_html.find("table", attrs={"class": "grid"})
        ban_headers = [th.text for th in ban_table.find_all("th")]
        ban_tbody = ban_table.find("tbody")
        ban_row_entries = ban_tbody.find_all("tr")
        ban_rows = self._parse_table(ban_row_entries)

        if len(ban_rows) == 1:
            try:
                if ban_rows[0][0].lower() == "there are no active session-bans":
                    return []
            except IndexError:
                pass

        # Unique ID field is more reliable as Steam ID
        # might be missing in the table in some cases.
        id_index = ban_headers.index(UNIQUE_ID_KEY)

        id_to_extra_data = {}
        steam_ids = []
        egs_ids = []

        for row in ban_rows:
            unique_id = row[id_index]

            try:
                int_id = int(unique_id, 16)

                # Session bans sometimes show a dummy ban.
                if int_id == 0:
                    continue

                is_steam_id = self._is_steam_id(int_id)
            except ValueError as ve:
                logger.exception(ve)
                logger.error("invalid Unique ID: '{uid}', skipping", uid=unique_id)
                continue

            extra_data = {
                key: value for key, value in zip(
                    ban_headers, row)
                if key.lower() != "actions"
            }

            if is_steam_id:
                steam_id = SteamID(int_id)
                steam_ids.append(steam_id)
                id_to_extra_data[steam_id] = extra_data
            else:
                egs_id = EGSID(int_id)
                egs_ids.append(egs_id)
                id_to_extra_data[egs_id] = extra_data

        persona_names = SteamWebAPI().get_persona_names(
            steam_ids=steam_ids
        )

        session_ban_wrappers = []

        for steam_id in steam_ids:
            persona_name = ""
            try:
                persona_name = persona_names[steam_id]
            except KeyError as ke:
                logger.debug(
                    "error getting persona name for Steam ID: {sid}",
                    sid=steam_id, exc_info=ke)

            extra_data = id_to_extra_data[steam_id]
            player_stats = {"Player Name": extra_data["Player Name"]}
            player = models.Player(ident=steam_id, persona_name=persona_name,
                                   stats=player_stats)

            ban = models.SessionBan(
                player=player,
                reason=extra_data["Reason"],
                admin=extra_data["Admin"],
                when=extra_data["When"],
            )

            session_ban_wrappers.append(adapters.SessionBanWrapper(
                ban=ban,
                adapter=adapter,
            ))

        for egs_id in egs_ids:
            extra_data = id_to_extra_data[egs_id]

            player_stats = {"Player Name": extra_data["Player Name"]}
            player = models.Player(ident=egs_id, stats=player_stats)

            ban = models.SessionBan(
                player=player,
                reason=extra_data["Reason"],
                admin=extra_data["Admin"],
                when=extra_data["When"],
            )

            session_ban_wrappers.append(adapters.SessionBanWrapper(
                ban=ban,
                adapter=adapter,
            ))

        return session_ban_wrappers

    def parse_fvri(self, resp: bytes):
        """Parse first visible row index from response."""
        parsed_html = self.parse_html(resp)
        return parsed_html.find(
            "input", attrs={"id": "__FirstVisibleRowIndex"}).get("value")

    def parse_has_next_page(self, resp: bytes):
        """Return True if next page button is enabled."""
        parsed_html = self.parse_html(resp)
        np_button = parsed_html.find(
            "button", attrs={"id": "__NextPage"})
        if not np_button:
            return False
        button_disabled = np_button.has_attr("disabled")
        return not button_disabled

    def parse_player_id_key(
            self, resp: bytes,
            player: Union[models.Player, adapters.PlayerWrapper]
    ) -> Tuple[int, str]:
        """Parse "hidden" player key and ID from players table."""
        parsed_html = self.parse_html(resp)
        trs = parsed_html.find_all("tr")
        player_id = -1
        player_key = ""

        for tr in trs:
            div = tr.find("div")
            if not div:
                continue

            # Find x from <input id = "__PlayerId_x">.
            x = div.find("input").get("id").split("_")[-1]
            div_player_key = div.find(
                "input", attrs={"id": f"__PlayerKey_{x}"}).get("value")
            div_player_name = div.find(
                "input", attrs={"id": f"__PlayerName_{x}"}).get("value")

            div_player_steam_id = div_player_key.split("_")[1].strip().lower()
            steam_id = player.steam_id.as_64
            # Match leading zeros of strings to compare.
            steam_id = f"{steam_id:#0{len(div_player_steam_id)}x}"
            steam_id = steam_id.strip().lower()

            if (steam_id == div_player_steam_id
                    and (div_player_name == player.name)):
                player_id = int(div.find(
                    "input", attrs={"id": f"__PlayerId_{x}"}).get("value"))
                player_key = div_player_key
                break

        return player_id, player_key

    def parse_members(self, resp: bytes,
                      adapter: adapters.WebAdminAdapter
                      ) -> List[adapters.MemberWrapper]:
        parsed_html = self.parse_html(resp)
        members_table = parsed_html.find("table", attrs={"id": "members"})
        members_headers = [th.text for th in members_table.find_all("th")]
        tracking_tbody = members_table.find("tbody")
        tb_row_entries = tracking_tbody.find_all("tr")
        members_rows = self._parse_table(tb_row_entries)

        id_index = members_headers.index(UNIQUE_ID_KEY)

        id_to_extra_data = {}
        steam_ids = []
        egs_ids = []

        for row in members_rows:
            unique_id = row[id_index]

            try:
                int_id = int(unique_id, 16)
                is_steam_id = self._is_steam_id(int_id)
            except ValueError as ve:
                logger.exception(ve)
                logger.error("invalid Unique ID: '{uid}', skipping", uid=unique_id)
                continue

            tracking_data = {
                key: value for key, value in zip(
                    members_headers, row)
                if key.lower() != "actions"
            }

            if is_steam_id:
                steam_id = SteamID(int_id)
                steam_ids.append(steam_id)
                id_to_extra_data[steam_id] = tracking_data
            else:
                egs_id = EGSID(int_id)
                egs_ids.append(egs_id)
                id_to_extra_data[egs_id] = tracking_data

        persona_names = SteamWebAPI().get_persona_names(
            steam_ids=steam_ids
        )

        member_wrappers = []

        for steam_id in steam_ids:
            persona_name = ""
            try:
                persona_name = persona_names[steam_id]
            except KeyError as ke:
                logger.error(
                    "error getting persona name for Steam ID: {sid}",
                    sid=steam_id)
                logger.exception(ke)

            extra_data = id_to_extra_data[steam_id]
            player = models.Player(ident=steam_id, persona_name=persona_name)

            member_wrappers.append(adapters.MemberWrapper(
                player=player,
                member_data=extra_data,
                adapter=adapter,
            ))

        for egs_id in egs_ids:
            extra_data = id_to_extra_data[egs_id]

            player = models.Player(ident=egs_id)

            member_wrappers.append(adapters.MemberWrapper(
                player=player,
                member_data=extra_data,
                adapter=adapter,
            ))

        return member_wrappers

    @staticmethod
    def parse_chat_message(div: BeautifulSoup) -> models.ChatMessage:
        teamcolor = str(div.find(
            "span", attrs={"class": "teamcolor"}).get("style"))
        if not teamcolor:
            logger.error(
                "no teamcolor in chat message div={div}", div=div)
        else:
            try:
                match = re.match(TEAMCOLOR_PATTERN, teamcolor)
                if match:
                    teamcolor = match.groups()[0]
            except IndexError as ie:
                logger.error("error getting teamcolor: {e}", e=ie)

        teamnotice = div.find("span", attrs={"class": "teamnotice"})
        if teamnotice:
            teamnotice = teamnotice.text

        name = div.find("span", attrs={"class": "username"})
        if name:
            name = name.text

        msg = div.find("span", attrs={"class": "message"})
        if msg:
            msg = msg.text

        return models.ChatMessage(
            sender=name,
            text=msg,
            team=models.Team.from_hex_color(str(teamcolor)),
            channel=models.ChatChannel.from_teamnotice(teamnotice)
        )

    @staticmethod
    def _parse_table(row_elements: Sequence) -> List[List[str]]:
        all_cols = []
        for row in row_elements:
            cols = row.find_all("td")
            cols = [ele.get_text(" ").strip() for ele in cols]
            if not cols:
                continue
            all_cols.append(cols)
        return all_cols

    @staticmethod
    @lru_cache(maxsize=64)
    def _is_steam_id(unique_id: Union[str, int]) -> bool:
        """Best-effort check whether hex-string or integer is Steam ID.

        :param unique_id: Unique ID hex-string or integer.
        :return: True if Steam ID.
        """
        if isinstance(unique_id, str):
            try:
                unique_id = int(unique_id, 16)
            except ValueError:
                raise ValueError(f"unable to convert Unique ID "
                                 f"'{unique_id}' to int")

        # Very likely a Steam ID.
        return len(str(unique_id)) == 17

    @staticmethod
    @lru_cache(maxsize=64)
    def _id_to_player(unique_id: str) -> models.Player:
        raise NotImplementedError
