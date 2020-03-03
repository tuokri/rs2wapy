import re
import sys
from typing import List
from typing import Sequence

from bs4 import BeautifulSoup
from logbook import Logger
from logbook import StreamHandler

import rs2wapy.models as models

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)

TEAMCOLOR_PATTERN = re.compile(r"background: (.*);")


class RS2WebAdminResponseParser:

    def __init__(self, encoding: str):
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

    @staticmethod
    def parse_chat_message(div: BeautifulSoup) -> models.ChatMessage:
        teamcolor = str(div.find(
            "span", attrs={"class": "teamcolor"}).get("style"))
        if not teamcolor:
            logger.error(
                "no teamcolor in chat message div={div}", div=div)
        else:
            try:
                teamcolor = re.match(TEAMCOLOR_PATTERN, teamcolor).groups()[0]
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
        parsed_html = self.parse_html(resp)

        info = {}
        rules = {}

        logger.info("parsing Ranked status")
        ranked = parsed_html.find(
            "span", attrs={"class": "ranked"}).text
        ranked = True if ranked.lower() == "ranked: yes" else False
        info["Ranked"] = ranked

        logger.info("parsing player scoreboard")
        player_scoreboard_table = parsed_html.find(
            "table", attrs={"id": "players"})
        player_scoreboard = models.PlayerScoreboard()
        player_scoreboard_thead = player_scoreboard_table.find("thead")
        headers = player_scoreboard_thead.find_all(
            "a", attrs={"class": "sortable"})
        header = ["Team"]
        header.extend([h.text.strip() for h in headers])
        header.extend(["Admin", "Spectator"])
        player_scoreboard.header = header

        row_elements = player_scoreboard_table.find_all("tr")
        scoreboard_parsed = self._parse_table(row_elements)
        for cols in scoreboard_parsed:
            cols[0] = "North" if cols[0] == "0" else "South"
            player_scoreboard.append(cols)

        logger.info("parsing team scoreboard")
        team_scoreboard_table = parsed_html.find(
            "table", attrs={"id": "teams"})
        team_scoreboard = models.TeamScoreboard()
        team_scoreboard_thead = team_scoreboard_table.find("thead")
        headers = team_scoreboard_thead.find_all("th")
        headers = [h.text.strip() for h in headers if h.text.strip()]
        team_scoreboard.header = headers

        row_elements = team_scoreboard_table.find_all("tr")
        scoreboard_parsed = self._parse_table(row_elements)
        for cols in scoreboard_parsed:
            cols = cols[1:]
            if not len(cols) == len(scoreboard_parsed[0]):
                cols.append("")
            team_scoreboard.append(cols)

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

    def parse_players(self, resp: bytes) -> dict:
        parsed_html = self.parse_html(resp)

        player_table = parsed_html.find("tbody")
        player_table = player_table.find_all("tr")
        player_table = self._parse_table(player_table)

        player_headers = parsed_html.find("thead")
        player_headers = [
            ph.text for ph in player_headers.find_all(
                "th", attrs={"class": "header"}
            )
        ]

        players = {}
        for element in player_table:
            p = models.Player(
                rs2_name=element[1],
                steam_id=element[4],
            )
            players[p] = element

        return players

    @staticmethod
    def _parse_table(row_elements: Sequence) -> List[List[str]]:
        all_cols = []
        for row in row_elements:
            cols = row.find_all("td")
            cols = [ele.text.strip() for ele in cols]
            if not cols:
                continue
            cols = [ele for ele in cols if ele]
            all_cols.append(cols)
        return all_cols
