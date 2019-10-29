import hashlib
import logging
import re
import sys
import time
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from typing import Tuple
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse

import pycurl
from bs4 import BeautifulSoup
from logbook import Logger, StreamHandler

HEADERS_MAX_LEN = 50

WEB_ADMIN_BASE_PATH = Path("/ServerAdmin/")
WEB_ADMIN_CURRENT_GAME_PATH = WEB_ADMIN_BASE_PATH / Path("/current/")
WEB_ADMIN_CHAT_PATH = WEB_ADMIN_CURRENT_GAME_PATH / Path("/chat")

StreamHandler(sys.stdout, level=logging.WARN).push_application()
logger = Logger(__name__)


def _read_encoding(headers: dict, index: int = -1) -> str:
    encoding = None
    if "content-type" in headers:
        content_type = headers["content-type"][index].lower()
        match = re.search(r"charset=(\S+)", content_type)
        if match:
            encoding = match.group(1)
            logger.debug("read_encoding(): encoding is {enc}", enc=encoding)
    if encoding is None:
        # Default encoding for HTML is iso-8859-1.
        # Other content types may have different default encoding,
        # or in case of binary data, may have no encoding at all.
        encoding = "iso-8859-1"
        logger.debug("read_encoding(): assuming encoding is {enc}", enc=encoding)
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


class RS2WebAdmin(object):
    """

    """
    BASE_HEADER = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.7,fi;q=0.3",
        "DNT": 1,
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": 1,
    }

    def __init__(self, username: str, password: str, webadmin_url: str):
        self._headers = {}
        self._username = username
        self._password = password
        self._auth_data = None

        self._url = webadmin_url

        scheme, netloc, path, params, query, fragment = urlparse(self._url)
        logger.debug("webadmin_url={url}, scheme={scheme}, netloc={netloc}, path={path}, params={params}, "
                     "query={query}, fragment={fragment}", url=self._url, scheme=scheme, netloc=netloc,
                     path=path, params=params, query=query, fragment=fragment)

        if not path:
            path = WEB_ADMIN_BASE_PATH.as_posix()

        self._url = urlunparse(
            (scheme, netloc, path, params, query, fragment))
        self._chat_url = urlunparse(
            (scheme, netloc, WEB_ADMIN_CHAT_PATH.as_posix(), params, query, fragment))
        self._current_game_url = urlunparse(
            (scheme, netloc, WEB_ADMIN_CURRENT_GAME_PATH.as_posix(), params, query, fragment))

        self._authenticate(
            login_url=self._url, username=self._username, password=self._password)

    @property
    def auth_data(self) -> AuthData:
        return self._auth_data

    @auth_data.setter
    def auth_data(self, auth_data: AuthData):
        self._auth_data = auth_data

    def get_chat_messages(self) -> Tuple[bytes, int]:
        logger.debug("get_chat_messages() called")

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
        return self._perform(c, self._chat_url, header)

    def get_ranked_status(self) -> str:
        logger.debug("get_server_ranked_status() called")

        sessionid = self._auth_data.sessionid
        authcred = self._auth_data.authcred
        authtimeout = self._auth_data.authtimeout

        header = self.BASE_HEADER.copy()
        header["Cookie"] = f"{sessionid}; {authcred}; {authtimeout}"

        c = pycurl.Curl()
        resp, _ = self._perform(c, self._current_game_url, header)

        # TODO: modularize?
        encoding = _read_encoding(self._headers)
        parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
        ranked_status = parsed_html.find("span", attrs={"class": "ranked"})
        return ranked_status.text

    def _perform(self, c: pycurl.Curl, url: str, header: dict = None) -> Tuple[bytes, int]:
        logger.debug("_perform() on url={url}, header={header}", url=url, header=header)

        if self._auth_timed_out(self._auth_data):
            self._authenticate(self._url, self._username, self._password)

        if not header:
            header = self.BASE_HEADER
        header = self._prepare_header(header)

        logger.debug("_perform(): prepared header={h}", h=header)

        buffer = BytesIO()

        c.setopt(c.WRITEFUNCTION, buffer.write)
        c.setopt(c.HEADERFUNCTION, self._header_function)
        c.setopt(c.BUFFERSIZE, 102400)
        c.setopt(c.URL, url)
        c.setopt(c.HTTPHEADER, header)
        c.setopt(c.USERAGENT, "curl/7.65.1")
        c.setopt(c.MAXREDIRS, 50)
        # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
        c.setopt(c.ACCEPT_ENCODING, "")
        # c.setopt(c.HTTP09_ALLOWED, True)
        c.setopt(c.TCP_KEEPALIVE, 1)
        c.setopt(c.FOLLOWLOCATION, True)

        c.perform()

        status = c.getinfo(pycurl.HTTP_CODE)
        logger.debug("_perform() HTTP status: {s}", s=status)
        c.close()

        if not status == HTTPStatus.OK:
            logger.error("_perform(): HTTP status error: {s}", s=status)

        if not status == HTTPStatus.OK:
            raise HTTPError(self._url, status, "error connecting to WebAdmin", fp=None, hdrs=None)

        return buffer.getvalue(), status

    def _header_function(self, header_line):

        if "connection" in self._headers:
            try:
                if len(self._headers["connection"]) > HEADERS_MAX_LEN:
                    logger.debug("Headers 'connection' values max length ({le}) exceeded, "
                                 "resetting _headers (preserving latest entries)",
                                 le=HEADERS_MAX_LEN)
                    new_headers = {}
                    for k, v in self._headers.items():
                        new_headers[k] = v[-1]
                    self._headers = new_headers
                    logger.debug("Headers 'connection' {t} new length={le}",
                                 t=type(self._headers["connection"]),
                                 le=len(self._headers["connection"]))
            except KeyError as ke:
                logger.error("header_function(): error: {e}", e=ke, exc_info=True)
            except IndexError as ie:
                logger.error("header_function(): error: {e}", e=ie, exc_info=True)

        # HTTP standard specifies that _headers are encoded in iso-8859-1.
        header_line = header_line.decode("iso-8859-1")

        # Header lines include the first status line (HTTP/1.x ...).
        # We are going to ignore all lines that don't have a colon in them.
        # This will botch _headers that are split on multiple lines...
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
        logger.debug("find_sessionid() called")

        # 'sessionid="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        r = ""
        try:
            if type(self._headers["set-cookie"]) == str:
                logger.debug("type(self._headers['set-cookie']) == str")
                r = re.search(r'sessionid="(.*?)"', self._headers["set-cookie"]).group(1)
            elif type(self._headers["set-cookie"]) == list:
                logger.debug("type(self._headers['set-cookie']) == list")
                sessionid_match = [i for i in self._headers["set-cookie"] if i.startswith("sessionid=")][-1]
                logger.debug("find_sessionid(): sessionid_match: {si}", si=sessionid_match)
                r = re.search(r'sessionid="(.*?)"', sessionid_match).group(1)
            else:
                logger.error("type(_headers['set-cookie']) == {t}", t=type(self._headers["set-cookie"]))
                logger.error("cant get sessionid from _headers")
                return r
        except AttributeError as ae:
            logger.error("find_sessionid(): error: {e}", e=ae)
            return r
        except Exception as e:
            logger.error("find_sessionid(): error: {}", e=e, exc_info=True)
            return r

        return f'sessionid="{r}";'

    def _get(self, url: str) -> Tuple[bytes, int]:
        logger.debug("get called")
        c = pycurl.Curl()
        return self._perform(c, url)

    def _post_login(self, url: str, sessionid: str, token: str, username: str, password: str,
                    remember=2678400) -> Tuple[bytes, int]:
        logger.debug("post_login() called")

        header = self.BASE_HEADER.copy()
        header["Referer"] = "http://81.19.210.136:1005/"
        header["Cookie"] = sessionid
        header["Content-Type"] = "application/x-www-form-urlencoded"

        password_hash = hashlib.sha1(
            bytearray(password, "utf-8") + bytearray(username, "utf-8")).hexdigest()

        postfields = (f"token={token}&password_hash=%24sha1%24{password_hash}"
                      + f"&username={username}&password=&remember={remember}")
        postfieldsize = len(postfields)

        logger.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)
        logger.debug("postfields: {pf}", pf=postfields)

        c = pycurl.Curl()
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        return self._perform(c, url, header)

    def _authenticate(self, login_url: str, username: str, password: str):
        logger.debug("authenticate() called")

        resp, _ = self._get(login_url)
        if not resp:
            logger.warn("no response content from url={url}", url=login_url)

        encoding = _read_encoding(self._headers, -1)
        parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
        token = ""
        try:
            token = parsed_html.find("input", attrs={"name": "token"}).get("value")
        except AttributeError as ae:
            logger.warn("unable to get token: {e}", e=ae)

        logger.debug("token: {token}", token=token)

        sessionid = self._find_sessionid()
        logger.debug("authenticate(): got sessionid: {si}, from headers", si=sessionid)

        self._post_login(login_url, sessionid=sessionid,
                         token=token, username=username, password=password)

        authcred = [i for i in self._headers["set-cookie"] if i.startswith("authcred=")][-1]
        authtimeout = [i for i in self._headers["set-cookie"] if i.startswith("authtimeout=")][-1]

        authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

        logger.debug("authcred: {ac}", ac=authcred)
        logger.debug("authtimeout: {ato}", ato=authtimeout)
        logger.debug("authtimeout_value: {ato_value}", ato_value=authtimeout_value)

        self._auth_data = AuthData(timeout=authtimeout_value, authcred=authcred, sessionid=sessionid,
                                   timeout_start=time.time(), authtimeout=authtimeout)

    @staticmethod
    def _prepare_header(header: dict) -> list:
        """
        Convert header dictionary to list for pycurl.
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
                    "auth_timed_out(): cannot calculate authentication timeout for timeout: {t}",
                    t=timeout)
            else:
                time_now = time.time()
                if (start_time + timeout) < time_now:
                    logger.debug(
                        "auth_timed_out(): authentication timed out for start_time={s}, "
                        "timeout={t}, time_now={tn}", s=start_time, t=timeout, tn=time_now)
                    return True
        return False
