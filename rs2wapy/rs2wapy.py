import hashlib
import re
import time
from http import HTTPStatus
from io import BytesIO
from typing import Tuple
from urllib.error import HTTPError

import logbook
import pycurl
from bs4 import BeautifulSoup

HEADERS_MAX_LEN = 50


def _read_encoding(headers: dict, index: int) -> str:
    encoding = None
    if "content-type" in headers:
        content_type = headers["content-type"][index].lower()
        match = re.search(r"charset=(\S+)", content_type)
        if match:
            encoding = match.group(1)
            logbook.debug("read_encoding(): encoding is {enc}", enc=encoding)
    if encoding is None:
        # Default encoding for HTML is iso-8859-1.
        # Other content types may have different default encoding,
        # or in case of binary data, may have no encoding at all.
        encoding = "iso-8859-1"
        logbook.debug("read_encoding(): assuming encoding is {enc}", enc=encoding)
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
        self._url = webadmin_url
        self._auth_data = None
        self._username = username
        self._password = password
        self._authenticate(login_url=self._url, username=username, password=password)

    def get_chat_messages(self, url: str, sessionid: str, authcred: str,
                          authtimeout: int) -> Tuple[bytes, int]:
        logbook.debug("get_messages() called")

        header = self.BASE_HEADER.copy()
        header["Cookie"] = f"{sessionid}; {authcred}; {authtimeout}"
        header["X-Requested-With"] = "XMLHttpRequest"
        header["Accept"] = "*/*"

        postfields = "ajax=1"
        postfieldsize = len(postfields)
        logbook.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)

        c = pycurl.Curl()
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        return self._perform(c, url, header)

    def _perform(self, c: pycurl.Curl, url: str, header: dict = None) -> Tuple[bytes, int]:
        logbook.debug("_perform() on url={url}, header={header}", url=url, header=header)

        if self._auth_timed_out(self._auth_data):
            self._authenticate(self._url, self._username, self._password)

        if not header:
            header = self.BASE_HEADER
        header = self._prepare_header(header)

        logbook.debug("_perform(): prepared header={h}", h=header)

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
        logbook.debug("_perform() HTTP status: {s}", s=status)
        if not status == HTTPStatus.OK:
            logbook.error("_perform(): HTTP status error: {s}", s=status)

        c.close()
        return bytes(), status

    def _header_function(self, header_line):

        if "connection" in self._headers:
            try:
                if len(self._headers["connection"]) > HEADERS_MAX_LEN:
                    logbook.debug("Headers 'connection' values max length ({le}) exceeded, "
                                  "resetting _headers (preserving latest entries)",
                                  le=HEADERS_MAX_LEN)
                    new_headers = {}
                    for k, v in self._headers.items():
                        new_headers[k] = v[-1]
                    self._headers = new_headers
                    logbook.debug("Headers 'connection' {t} new length={le}",
                                  t=type(self._headers["connection"]),
                                  le=len(self._headers["connection"]))
            except KeyError as ke:
                logbook.error("header_function(): error: {e}", e=ke, exc_info=True)
            except IndexError as ie:
                logbook.error("header_function(): error: {e}", e=ie, exc_info=True)

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
        logbook.debug("find_sessionid() called")

        # 'sessionid="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        r = ""
        try:
            if type(self._headers["set-cookie"]) == str:
                logbook.debug("type(self._headers['set-cookie']) == str")
                r = re.search(r'sessionid="(.*?)"', self._headers["set-cookie"]).group(1)
            elif type(self._headers["set-cookie"]) == list:
                logbook.debug("type(self._headers['set-cookie']) == list")
                sessionid_match = [i for i in self._headers["set-cookie"] if i.startswith("sessionid=")][-1]
                logbook.debug("find_sessionid(): sessionid_match: {si}", si=sessionid_match)
                r = re.search(r'sessionid="(.*?)"', sessionid_match).group(1)
            else:
                logbook.error("type(_headers['set-cookie']) == {t}", t=type(self._headers["set-cookie"]))
                logbook.error("cant get sessionid from _headers")
                return r
        except AttributeError as ae:
            logbook.error("find_sessionid(): error: {e}", e=ae)
            return r
        except Exception as e:
            logbook.error("find_sessionid(): error: {}", e=e, exc_info=True)
            return r

        return f'sessionid="{r}";'

    def _get(self, url: str) -> Tuple[bytes, int]:
        logbook.debug("get called")
        c = pycurl.Curl()
        return self._perform(c, url)

    def _post_login(self, url: str, sessionid: str, token: str, username: str, password: str,
                    remember=2678400) -> Tuple[bytes, int]:
        logbook.debug("post_login() called")

        header = self.BASE_HEADER.copy()
        header["Referer"] = "http://81.19.210.136:1005/"
        header["Cookie"] = sessionid
        header["Content-Type"] = "application/x-www-form-urlencoded"

        password_hash = hashlib.sha1(
            bytearray(password, "utf-8") + bytearray(username, "utf-8")).hexdigest()

        postfields = (f"token={token}&password_hash=%24sha1%24{password_hash}"
                      + f"&username={username}&password=&remember={remember}")
        postfieldsize = len(postfields)

        logbook.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)
        logbook.debug("postfields: {pf}", pf=postfields)

        c = pycurl.Curl()
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        return self._perform(c, url, header)

    def _authenticate(self, login_url: str, username: str, password: str):
        logbook.debug("authenticate() called")

        resp, status = self._get(login_url)
        if not status == HTTPStatus.OK:
            raise HTTPError(self._url, status, "error connecting to WebAdmin", fp=None, hdrs=None)

        encoding = _read_encoding(self._headers, -1)
        parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
        token = parsed_html.find("input", attrs={"name": "token"}).get("value")
        logbook.debug("token: {token}", token=token)

        sessionid = self._find_sessionid()
        logbook.debug("authenticate(): got sessionid: {si}, from headers", si=sessionid)

        self._post_login(login_url, sessionid=sessionid,
                         token=token, username=username, password=password)

        authcred = [i for i in self._headers["set-cookie"] if i.startswith("authcred=")][-1]
        authtimeout = [i for i in self._headers["set-cookie"] if i.startswith("authtimeout=")][-1]

        authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

        logbook.debug("authcred: {ac}", ac=authcred)
        logbook.debug("authtimeout: {ato}", ato=authtimeout)
        logbook.debug("authtimeout_value: {ato_value}", ato_value=authtimeout_value)

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
        if not auth_data:
            return False
        else:
            timeout = auth_data.timeout
            start_time = auth_data.timeout_start

        if timeout < 0:
            logbook.error(
                "auth_timed_out(): cannot calculate authentication timeout for timeout: {t}",
                t=timeout)
        else:
            time_now = time.time()
            if (start_time + timeout) < time_now:
                logbook.debug(
                    "auth_timed_out(): authentication timed out for start_time={s}, "
                    "timeout={t}, time_now={tn}", s=start_time, t=timeout, tn=time_now)
                return True

        return False
