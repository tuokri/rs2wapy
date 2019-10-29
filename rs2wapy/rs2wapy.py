import hashlib
import re
import time
from io import BytesIO

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
    def __init__(self, timeout: int, authcred: str, sessionid: str, authtimeout: str):
        self._timeout = int(timeout)
        self._authcred = authcred
        self._sessionid = sessionid
        self._authtimeout = authtimeout

    @property
    def timeout(self) -> int:
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
    def authtimeout(self) -> str:
        return self._authtimeout


class RS2WebAdmin(object):
    def __init__(self):
        self.headers = {}

    def header_function(self, header_line):

        if "connection" in self.headers:
            try:
                if len(self.headers["connection"]) > HEADERS_MAX_LEN:
                    logbook.info(("Headers 'connection' values max length ({le}) exceeded, resetting headers "
                                  + "(preserving latest entries)"), le=HEADERS_MAX_LEN)
                    new_headers = {}
                    for k, v in self.headers.items():
                        new_headers[k] = v[-1]
                    self.headers = new_headers
                    logbook.info("Headers 'connection' {conn} new length={le}",
                                 conn=type(self.headers["connection"]), le=len(self.headers["connection"]))
            except KeyError as ke:
                logbook.error("header_function(): error: {e}", e=ke, exc_info=True)
            except IndexError as ie:
                logbook.error("header_function(): error: {e}", e=ie, exc_info=True)

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

        if name in self.headers:
            if isinstance(self.headers[name], list):
                self.headers[name].append(value)
            else:
                self.headers[name] = [self.headers[name], value]
        else:
            self.headers[name] = value

    def get_login(self, c: pycurl.Curl, url: str) -> bytes:
        logbook.debug("get_login() called")

        buffer = BytesIO()

        header = [
            "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
            "DNT: 1",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
        ]

        c.setopt(c.WRITEFUNCTION, buffer.write)
        c.setopt(c.HEADERFUNCTION, self.header_function)

        c.setopt(c.BUFFERSIZE, 102400)
        c.setopt(c.URL, url)
        c.setopt(c.HTTPHEADER, header)
        c.setopt(c.USERAGENT, "curl/7.65.1")
        c.setopt(c.MAXREDIRS, 50)
        # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
        c.setopt(c.ACCEPT_ENCODING, "")
        # c.setopt(c.HTTP09_ALLOWED, 1)
        c.setopt(c.TCP_KEEPALIVE, 1)
        c.setopt(c.FOLLOWLOCATION, True)

        c.perform()
        logbook.info("get_login() HTTP response: {c}", c=c.getinfo(c.HTTP_CODE))
        return buffer.getvalue()

    def post_login(self, c: pycurl.Curl, url: str, sessionid: str, token: str, username: str, password: str,
                   remember=2678400) -> bytes:
        logbook.info("post_login() called")

        buffer = BytesIO()

        header = [
            "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
            "Referer: http://81.19.210.136:1005/",
            "Content-Type: application/x-www-form-urlencoded",
            "DNT: 1",
            "Connection: keep-alive",
            f"Cookie: {sessionid}",
            "Upgrade-Insecure-Requests: 1",
        ]

        password_hash = hashlib.sha1(
            bytearray(password, "utf-8") + bytearray(username, "utf-8")).hexdigest()

        postfields = (f"token={token}&password_hash=%24sha1%24{password_hash}"
                      + f"&username={username}&password=&remember={remember}")
        postfieldsize = len(postfields)
        logbook.debug("postfieldsize: {pf_size}", pf_size=postfieldsize)

        logbook.debug("postfields: {pf}", pf=postfields)

        c.setopt(c.WRITEFUNCTION, buffer.write)
        c.setopt(c.HEADERFUNCTION, self.header_function)

        c.setopt(c.BUFFERSIZE, 102400)
        c.setopt(c.URL, url)
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        c.setopt(c.HTTPHEADER, header)
        c.setopt(c.USERAGENT, "curl/7.65.1")
        c.setopt(c.MAXREDIRS, 50)
        # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
        c.setopt(c.ACCEPT_ENCODING, "")
        # c.setopt(c.HTTP09_ALLOWED, True)
        c.setopt(c.TCP_KEEPALIVE, 1)
        c.setopt(c.FOLLOWLOCATION, True)

        c.perform()
        logbook.info("post_login() HTTP response: {c}", c=c.getinfo(c.HTTP_CODE))
        return buffer.getvalue()

    def get_messages(self, c: pycurl.Curl, url: str, sessionid: str, authcred: str, authtimeout: int) -> bytes:
        logbook.info("get_messages() called")

        buffer = BytesIO()

        header = [
            "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
            "Referer: http://81.19.210.136:1005/",
            "Content-Type: application/x-www-form-urlencoded",
            "X-Requested-With: XMLHttpRequest",
            "DNT: 1",
            "Connection: keep-alive",
            f"Cookie: {sessionid}; {authcred}; {authtimeout}",
            "Upgrade-Insecure-Requests: 1",
        ]

        postfields = "ajax=1"
        postfieldsize = len(postfields)
        logbook.info("postfieldsize: {pf_size}", pf_size=postfieldsize)

        c.setopt(c.WRITEFUNCTION, buffer.write)
        c.setopt(c.HEADERFUNCTION, self.header_function)

        c.setopt(c.BUFFERSIZE, 102400)
        c.setopt(c.URL, url)
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
        c.setopt(c.HTTPHEADER, header)
        c.setopt(c.USERAGENT, "curl/7.65.1")
        c.setopt(c.MAXREDIRS, 50)
        # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
        c.setopt(c.ACCEPT_ENCODING, "")
        # c.setopt(c.HTTP09_ALLOWED, True)
        c.setopt(c.TCP_KEEPALIVE, 1)
        c.setopt(c.FOLLOWLOCATION, True)

        c.perform()
        logbook.info("get_messages() HTTP response: {c}", c=c.getinfo(c.HTTP_CODE))
        return buffer.getvalue()

    def find_sessionid(self, headers):
        logbook.info("find_sessionid() called")

        # 'sessionid="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        r = ""
        try:
            if type(headers["set-cookie"]) == str:
                logbook.debug("type(self.headers['set-cookie']) == str")
                r = re.search(r'sessionid="(.*?)"', self.headers["set-cookie"]).group(1)
            elif type(headers["set-cookie"]) == list:
                logbook.debug("type(self.headers['set-cookie']) == list")
                sessionid_match = [i for i in self.headers["set-cookie"] if i.startswith("sessionid=")][-1]
                logbook.debug("find_sessionid(): sessionid_match: {si}", si=sessionid_match)
                r = re.search(r'sessionid="(.*?)"', sessionid_match).group(1)
            else:
                logbook.error("type(headers['set-cookie']) == {t}", t=type(headers["set-cookie"]))
                logbook.error("cant get sessionid from headers")
                return r
        except AttributeError as ae:
            logbook.error("find_sessionid(): error: {e}", e=ae)
            return r
        except Exception as e:
            logbook.error("find_sessionid(): error: {}", e=e, exc_info=True)
            return r

        return f'sessionid="{r}";'

    def authenticate(self, login_url: str, username: str, password: str) -> AuthData:
        logbook.info("authenticate() called")

        c = pycurl.Curl()

        resp = self.get_login(c, login_url)
        encoding = _read_encoding(self.headers, -1)
        parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
        token = parsed_html.find("input", attrs={"name": "token"}).get("value")
        logbook.debug("token: {token}", token=token)

        sessionid = self.find_sessionid(self.headers)

        logbook.debug("authenticate(): got sessionid: {si}, from headers", si=sessionid)

        self.post_login(c, login_url, sessionid=sessionid,
                        token=token, username=username, password=password)

        authcred = [i for i in self.headers["set-cookie"] if i.startswith("authcred=")][-1]
        authtimeout = [i for i in self.headers["set-cookie"] if i.startswith("authtimeout=")][-1]

        authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

        logbook.debug("authcred: {ac}", ac=authcred)
        logbook.debug("authtimeout: {ato}", ato=authtimeout)
        logbook.info("authtimeout_value: {ato_value}", ato_value=authtimeout_value)

        c.close()
        return AuthData(timeout=authtimeout_value, authcred=authcred, sessionid=sessionid,
                        authtimeout=authtimeout)

    @staticmethod
    def auth_timed_out(start_time, timeout):
        if timeout <= 0:
            logbook.info(
                "auth_timed_out(): cannot calculate authentication timeout for timeout: {t}", t=timeout)
            return False

        time_now = time.time()
        if (start_time + timeout) < time_now:
            logbook.info(
                "auth_timed_out(): authentication timed out for start_time={s}, timeout={t}, time_now={tn}",
                s=start_time, t=timeout, tn=time_now)
            return True
        return False
