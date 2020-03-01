from typing import List

from bs4 import BeautifulSoup

import rs2wapy.models as models


class RS2WebAdminResponseParser:

    def __init__(self, encoding: str):
        self._encoding = encoding

    def parse_html(self, resp: bytes, encoding: str = None) -> BeautifulSoup:
        if not encoding:
            encoding = self._encoding
        return BeautifulSoup(resp.decode(encoding), features="html.parser")

    def parse_chat_messages(self, resp: bytes,
                            encoding: str = None) -> models.ChatMessages:
        parsed_html = self.parse_html(resp, encoding)
        chat_message_divs = parsed_html.find_all("div", attrs={"class": "chatmessage"})
        # chat_notice_divs = parsed_html.find_all("div", attrs={"class": "chatnotice"})
        cm = models.ChatMessages()
        for div in chat_message_divs:
            cm.append(self.parse_chat_message(div))
        return cm

    @staticmethod
    def parse_chat_message(div: BeautifulSoup) -> models.ChatMessage:
        # TODO: Parse further.
        teamcolor = str(div.find("span", attrs={"class": "teamcolor"}))
        teamnotice = str(div.find("span", attrs={"class": "teamnotice"}))
        name = str(div.find("span", attrs={"class": "username"}))
        msg = str(div.find("span", attrs={"class": "message"}))
        return models.ChatMessage(
            sender=name,
            text=msg,
            team=models.Team.from_hex_color(teamcolor),
            channel=models.ChatChannel.from_teamnotice(teamnotice)
        )

    # TODO: reconsider return type. Namedtuple or class?
    def parse_access_policy(self, resp: bytes, encoding: str = None) -> List[str]:
        parsed_html = self.parse_html(resp, encoding)
        policy_table = parsed_html.find("table", attrs={"id": "policies"})
        trs = policy_table.find_all("tr")
        policies = []
        for tr in trs:
            ip_mask = tr.find("input", attrs={"name": "ipmask"})
            policy = tr.find("option", attrs={"selected": "selected"})
            if ip_mask and policy:
                policies.append(f"{ip_mask.get('value')}: {policy.text.upper()}")
        return policies
