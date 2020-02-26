import asyncio
import hashlib
import re
import sys
import time
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from typing import List
from typing import Sequence
from typing import Tuple
from urllib.parse import urlparse
from urllib.parse import urlunparse

import pycurl
from bs4 import BeautifulSoup
from logbook import Logger
from logbook import StreamHandler
from requests import HTTPError

from rs2wapy.models import models

StreamHandler(sys.stdout, level="WARNING").push_application()
logger = Logger(__name__)

HEADERS_MAX_LEN = 50
CURL_USERAGENT = f"curl/{pycurl.version_info()[1]}"
POLICIES = ["ACCEPT", "DENY"]

WEB_ADMIN_BASE_PATH = Path("/ServerAdmin/")
WEB_ADMIN_CURRENT_GAME_PATH = WEB_ADMIN_BASE_PATH / Path("current/")
WEB_ADMIN_CHAT_PATH = WEB_ADMIN_CURRENT_GAME_PATH / Path("chat/")
WEB_ADMIN_ACCESS_POLICY_PATH = WEB_ADMIN_BASE_PATH / Path("policy/")


def _in(el: object, seq: Sequence[Sequence]) -> bool:
    """Check if element is in any sequence of sequences."""
    for s in seq:
        if el in s:
            return True
    return False


def _read_encoding(headers: dict, index: int = -1) -> str:
    encoding = None
    if "content-type" in headers:
        content_type = headers["content-type"][index].lower()
        match = re.search(r"charset=(\S+)", content_type)
        if match:
            encoding = match.group(1)
            logger.debug("encoding is {enc}", enc=encoding)
    if encoding is None:
        # Default encoding for HTML is iso-8859-1.
        # Other content types may have different default encoding,
        # or in case of binary data, may have no encoding at all.
        encoding = "iso-8859-1"
        logger.debug("assuming encoding is {enc}", enc=encoding)
    return encoding


class AuthData(object):
    def __init__(self, timeout: float, authcred: str, sessionid: str,
                 timeout_start: float, authtimeout: str):
        self._timeout = float(timeout)
        self._authcred = authcred
        self._sessionid = sessionid
        self._timeout_start = timeout_start
        self._authtimeout = authtimeout

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def authcred(self) -> str:
        return self._authcred

    @property
    def sessionid(self) -> str:
        return self._sessionid

    @sessionid.setter
    def sessionid(self, sessionid: str):
        self._sessionid = sessionid

    @property
    def timeout_start(self):
        return self._timeout_start

    @timeout_start.setter
    def timeout_start(self, timeout_start: float):
        self.timeout_start = timeout_start

    @property
    def authtimeout(self) -> str:
        return self._authtimeout


class Adapter(object):
    BASE_HEADER = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.7,fi;q=0.3",
        "DNT": 1,
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": 1,
        "Referer": "",
    }

    def __init__(self, username: str, password: str, webadmin_url: str):
        self._headers = {}
        self._username = username
        self._password_hash = hashlib.sha1(
            bytearray(password, "utf-8") + bytearray(username, "utf-8")).hexdigest()
        self._auth_data = None
        self._webadmin_url = webadmin_url

        scheme, netloc, path, params, query, fragment = urlparse(self._webadmin_url)
        logger.debug("webadmin_url={url}, scheme={scheme}, netloc={netloc}, "
                     "path={path}, params={params}, query={query}, fragment={fragment}",
                     url=self._webadmin_url, scheme=scheme, netloc=netloc,
                     path=path, params=params, query=query, fragment=fragment)

        if (not path) or (path == "/"):
            path = WEB_ADMIN_BASE_PATH.as_posix()

        referer = ""
        if not scheme and not netloc:
            referer = path
        elif netloc:
            referer = netloc

        if not referer:
            logger.warning("unable to set 'Referer' in header")
        else:
            self.BASE_HEADER["Referer"] = referer
            logger.debug("setting 'Referer' to '{r}'", r=referer)

        self._webadmin_url = urlunparse(
            (scheme, netloc, path, params, query, fragment))
        self._chat_url = urlunparse(
            (scheme, netloc, WEB_ADMIN_CHAT_PATH.as_posix(), params, query, fragment))
        self._current_game_url = urlunparse(
            (scheme, netloc, WEB_ADMIN_CURRENT_GAME_PATH.as_posix(), params, query, fragment))
        self._access_policy_url = urlunparse(
            (scheme, netloc, WEB_ADMIN_ACCESS_POLICY_PATH.as_posix(), params, query, fragment))

        self._authenticate()

    @property
    def auth_data(self) -> AuthData:
        return self._auth_data

    @auth_data.setter
    def auth_data(self, auth_data: AuthData):
        self._auth_data = auth_data

    def get_chat(self) -> models.Chat:
        pass

    def get_chat_messages(self) -> Tuple[bytes, int]:
        sessionid = self._auth_data.sessionid
        authcred = self._auth_data.authcred
        authtimeout = self._auth_data.authtimeout

        header = self.BASE_HEADER.copy()
        header["Cookie"] = f"{sessionid}; {authcred}; {authtimeout}"
        header["X-Requested-With"] = "XMLHttpRequest"
        header["Accept"] = "*/*"

        postfields = "ajax=1"
        postfieldsize = len(postfields)
        logger.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)

        c = pycurl.Curl()
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        return self._perform(self._chat_url, curl_obj=c, header=header)

    def get_ranked_status(self) -> str:
        sessionid = self._auth_data.sessionid
        authcred = self._auth_data.authcred
        authtimeout = self._auth_data.authtimeout

        header = self.BASE_HEADER.copy()
        header["Cookie"] = f"{sessionid}; {authcred}; {authtimeout}"

        c = pycurl.Curl()
        resp, _ = self._perform(self._current_game_url, curl_obj=c, header=header)

        parsed_html = self._parse_html(resp)
        ranked_status = parsed_html.find("span", attrs={"class": "ranked"})
        return ranked_status.text

    def get_access_policy(self) -> List[str]:
        sessionid = self._auth_data.sessionid
        authcred = self._auth_data.authcred
        authtimeout = self._auth_data.authtimeout

        header = self.BASE_HEADER.copy()
        header["Cookie"] = f"{sessionid}; {authcred}; {authtimeout}"
        header["Cache-Control"] = "no-cache"

        # Prevent caching with randomized parameter.
        url = f"{self._access_policy_url}?$(date +%s)"

        c = pycurl.Curl()
        resp, _ = self._perform(url, curl_obj=c, header=header)
        return self._parse_access_policy(resp)

    def add_access_policy(self, ip_mask: str, policy: str) -> bool:
        """
        Add IP access policy.

        :param ip_mask:
            IP mask of the policy to be added.
        :param policy:
            "DENY" or "ACCEPT".
        :return:
            True if policy added, else False.
        """
        policies = self.get_access_policy()
        if _in(ip_mask, policies):
            logger.info("{ip} already in policies", ip=ip_mask)
            return False

        policy = policy.upper()
        if policy not in POLICIES:
            raise ValueError(f"invalid policy: {policy}")

        action = "add"

        header = self.BASE_HEADER.copy()
        header["Content-Type"] = "application/x-www-form-urlencoded"

        max_retries = 10
        retries = 0

        # WORKAROUND:
        # There is an issue where the policy is not always added
        # even though the request is seemingly valid, but repeating
        # the request eventually successfully adds the policy.
        while not _in(ip_mask, policies) and (retries < max_retries):
            header["Cookie"] = self._find_sessionid()

            postfields = f"action={action}&ipmask={ip_mask}&policy={policy}"
            postfieldsize = len(postfields)

            logger.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)
            logger.debug("postfields: {pf}", pf=postfields)

            c = pycurl.Curl()
            c.setopt(c.POSTFIELDS, postfields)
            c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)

            try:
                self._perform(self._access_policy_url, curl_obj=c, header=header)
            except Exception as e:
                logger.error(e, exc_info=True)

            policies = self.get_access_policy()
            retries += 1

        if retries >= max_retries:
            logger.error("failed to add policy {p}, max retries exceeded", p=ip_mask)
            return False
        return True

    def delete_access_policy(self, ip_mask: str) -> bool:
        """
        Delete IP access policy.

        :param ip_mask:
            IP mask of the access policy to be deleted.
        :return:
            True if deleted, else False.
        """
        policies = self.get_access_policy()
        if not _in(ip_mask, policies):
            logger.info("{ip} not in policies, no need to delete", ip=ip_mask)
            return False

        action = "modify"

        header = self.BASE_HEADER.copy()
        header["Content-Type"] = "application/x-www-form-urlencoded"
        header["Accept-Encoding"] = "gzip, deflate"

        max_retries = 10
        retries = 0

        # WORKAROUND:
        # There is an issue where the policy is not always deleted
        # even though the request is seemingly valid, but repeating
        # the request eventually successfully deletes the policy.
        while _in(ip_mask, policies) and (retries < max_retries):
            header["Cookie"] = self._find_sessionid()

            try:
                argstr = self._policies_to_delete_argstr(policies, ip_mask)
            except IndexError as ie:
                logger.error("error finding index of {ipm}: {e}", ipm=ip_mask, e=ie)
                continue

            postfields = f"action={action}&{argstr}"
            postfieldsize = len(postfields)
            header["Content-Length"] = postfieldsize

            logger.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)
            logger.debug("postfields: {pf}", pf=postfields)

            c = pycurl.Curl()
            c.setopt(c.POSTFIELDS, postfields)
            c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)

            try:
                self._perform(self._access_policy_url, curl_obj=c, header=header)
            except Exception as e:
                logger.error(e, exc_info=True)

            policies = self.get_access_policy()
            retries += 1

        if retries >= max_retries:
            logger.error("failed to delete policy {p}, max retries exceeded", p=ip_mask)
            return False
        return True

    def update_access_policy(self, ip_mask: str, policy: str) -> bool:
        pass

    async def _async_perform(self, url: str, curl_obj: pycurl.Curl = None,
                             header: dict = None) -> Tuple[bytes, int]:
        await self._authenticated()

        if not curl_obj:
            curl_obj = pycurl.Curl()

        logger.debug("url={url}, header={header}", url=url, header=header)
        if not header:
            header = self.BASE_HEADER
        header = self._prepare_header(header)

        logger.debug("prepared header={h}", h=header)

        buffer = BytesIO()

        curl_obj.setopt(curl_obj.WRITEFUNCTION, buffer.write)
        curl_obj.setopt(curl_obj.HEADERFUNCTION, self._header_function)
        curl_obj.setopt(curl_obj.BUFFERSIZE, 102400)
        curl_obj.setopt(curl_obj.URL, url)
        curl_obj.setopt(curl_obj.HTTPHEADER, header)
        curl_obj.setopt(curl_obj.USERAGENT, CURL_USERAGENT)
        curl_obj.setopt(curl_obj.MAXREDIRS, 50)
        curl_obj.setopt(curl_obj.ACCEPT_ENCODING, "")
        curl_obj.setopt(curl_obj.TCP_KEEPALIVE, 1)
        curl_obj.setopt(curl_obj.FOLLOWLOCATION, True)

        curl_obj.perform()

        status = curl_obj.getinfo(pycurl.HTTP_CODE)
        logger.debug("HTTP status: {s}", s=status)
        curl_obj.close()

        if not status == HTTPStatus.OK:
            logger.error("HTTP status error: {s}", s=status)

        if not status == HTTPStatus.OK:
            raise HTTPError(self._webadmin_url, status, "error connecting to WebAdmin",
                            fp=None, hdrs=None)

        return buffer.getvalue(), status

    def _perform(self, url: str, curl_obj: pycurl.Curl = None,
                 header: dict = None) -> Tuple[bytes, int]:
        return asyncio.run(
            self._async_perform(url=url, curl_obj=curl_obj, header=header))

    def _header_function(self, header_line):

        if "connection" in self._headers:
            try:
                if len(self._headers["connection"]) > HEADERS_MAX_LEN:
                    logger.debug("Headers 'connection' values max length ({le}) exceeded, "
                                 "resetting headers (preserving latest entries)",
                                 le=HEADERS_MAX_LEN)
                    new_headers = {}
                    for k, v in self._headers.items():
                        new_headers[k] = v[-1]
                    self._headers = new_headers
                    logger.debug("Headers 'connection' {t} new length={le}",
                                 t=type(self._headers["connection"]),
                                 le=len(self._headers["connection"]))
            except (KeyError, IndexError) as e:
                logger.error("error: {e}", e=e, exc_info=True)

        # HTTP standard specifies that headers are encoded in iso-8859-1.
        header_line = header_line.decode("iso-8859-1")

        # Header lines include the first status line (HTTP/1.x ...).
        # We are going to ignore all lines that don't have a colon in them.
        # This will botch headers that are split on multiple lines...
        if ":" not in header_line:
            return

        # Break the header line into header name and value.
        name, value = header_line.split(":", 1)

        # Remove whitespace that may be present.
        # Header lines include the trailing newline, and there may be whitespace
        # around the colon.
        name = name.strip()
        value = value.strip()

        # Header names are case insensitive.
        # Lowercase name here.
        name = name.lower()

        if name in self._headers:
            if isinstance(self._headers[name], list):
                self._headers[name].append(value)
            else:
                self._headers[name] = [self._headers[name], value]
        else:
            self._headers[name] = value

    def _find_sessionid(self) -> str:
        """
        Find latest session ID in headers.
        """
        # 'sessionid="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        r = ""
        try:
            if type(self._headers["set-cookie"]) == str:
                logger.debug("type(self._headers['set-cookie']) == str")
                r = re.search(r'sessionid="(.*?)"', self._headers["set-cookie"]).group(1)
            elif type(self._headers["set-cookie"]) == list:
                logger.debug("type(self._headers['set-cookie']) == list")
                sessionid_match = [i for i in self._headers["set-cookie"] if i.startswith("sessionid=")][-1]
                logger.debug("sessionid_match: {si}", si=sessionid_match)
                r = re.search(r'sessionid="(.*?)"', sessionid_match).group(1)
            else:
                logger.error("type(_headers['set-cookie']) == {t}", t=type(self._headers["set-cookie"]))
                logger.error("cant get sessionid from headers")
                return r
        except AttributeError as ae:
            logger.error("error: {e}", e=ae)
            return r
        except Exception as e:
            logger.error("error: {e}", e=e, exc_info=True)
            return r

        return f'sessionid="{r}";'

    def _get(self, url: str) -> Tuple[bytes, int]:
        return self._perform(url=url)

    def _post_login(self, sessionid: str, token: str, remember=2678400) -> Tuple[bytes, int]:
        header = self.BASE_HEADER.copy()
        header["Cookie"] = sessionid
        header["Content-Type"] = "application/x-www-form-urlencoded"

        postfields = (f"token={token}&password_hash=%24sha1%24{self._password_hash}"
                      + f"&username={self._username}&password=&remember={remember}")
        postfieldsize = len(postfields)

        logger.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)
        logger.debug("postfields: {pf}", pf=postfields)

        c = pycurl.Curl()
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        return self._perform(self._webadmin_url, curl_obj=c, header=header)

    def _authenticate(self):
        resp, _ = self._get(self._webadmin_url)
        if not resp:
            logger.error("no response content from url={url}", url=self._webadmin_url)

        parsed_html = self._parse_html(resp)
        token = ""
        try:
            token = parsed_html.find("input", attrs={"name": "token"}).get("value")
        except AttributeError as ae:
            logger.error("unable to get token: {e}", e=ae)

        logger.debug("token: {token}", token=token)

        sessionid = self._find_sessionid()
        logger.debug("got sessionid: {si}, from headers", si=sessionid)

        self._post_login(sessionid=sessionid, token=token)

        authcred = [i for i in self._headers["set-cookie"] if i.startswith("authcred=")][-1]
        authtimeout = [i for i in self._headers["set-cookie"] if i.startswith("authtimeout=")][-1]

        authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

        logger.debug("authcred: {ac}", ac=authcred)
        logger.debug("authtimeout: {ato}", ato=authtimeout)
        logger.debug("authtimeout_value: {ato_value}", ato_value=authtimeout_value)

        self._auth_data = AuthData(timeout=authtimeout_value, authcred=authcred, sessionid=sessionid,
                                   timeout_start=time.time(), authtimeout=authtimeout)

    async def _authenticated(self):
        if self._auth_timed_out(self._auth_data):
            self._authenticate(self._webadmin_url)

    def _parse_html(self, resp) -> BeautifulSoup:
        encoding = _read_encoding(self._headers)
        return BeautifulSoup(resp.decode(encoding), features="html.parser")

    # TODO: reconsider return type. Namedtuple or class?
    def _parse_access_policy(self, resp) -> List[str]:
        parsed_html = self._parse_html(resp)
        policy_table = parsed_html.find("table", attrs={"id": "policies"})
        trs = policy_table.find_all("tr")
        policies = []
        for tr in trs:
            ip_mask = tr.find("input", attrs={"name": "ipmask"})
            policy = tr.find("option", attrs={"selected": "selected"})
            if ip_mask and policy:
                policies.append(f"{ip_mask.get('value')}: {policy.text.upper()}")
        return policies

    @staticmethod
    def _policies_to_delete_argstr(policies: List[str], to_delete: str) -> str:
        del_index = [idx for idx, s in enumerate(policies) if to_delete in s][0]
        policies = [p.split(":") for p in policies]
        policies = [(f"ipmask={p[0].strip()}&policy={p[1].strip()}"
                     f"{f'&delete={del_index}' if p[0] == to_delete else ''}")
                    for p in policies]
        return "&".join(policies)

    @staticmethod
    def _prepare_header(header: dict) -> list:
        """
        Convert header dictionary to list for PycURL.
        """
        return [f"{key}: {value}" for key, value in header.items()]

    @staticmethod
    def _auth_timed_out(auth_data: AuthData) -> bool:
        """
        Return True if authentication has timed out, else False.
        """
        if auth_data:
            timeout = auth_data.timeout
            start_time = auth_data.timeout_start

            if timeout < 0:
                logger.error(
                    "cannot calculate authentication timeout for timeout: {t}",
                    t=timeout)
            else:
                time_now = time.time()
                if (start_time + timeout) < time_now:
                    logger.debug(
                        "authentication timed out for start_time={s}, "
                        "timeout={t}, time_now={tn}", s=start_time, t=timeout, tn=time_now)
                    return True
        return False
