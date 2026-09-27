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

from __future__ import annotations

import os
import sys
from typing import Dict
from typing import List
from typing import Sequence

import httpx2
from cachetools import TTLCache
from cachetools import cached

from rs2wapy.logger import logger

from .steamid import SteamID

_ttl_cache: TTLCache = TTLCache(maxsize=256, ttl=60)


def _chunks(seq: Sequence, n: int):
    """Yield successive n-sized chunks from seq."""
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


class Singleton(type):
    _instances: Dict[type, Singleton] = {}

    def __call__(cls, *args, **kwargs):
        try:
            steam_api_key = os.environ["STEAM_WEB_API_KEY"]
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(
                    steam_api_key, *args, **kwargs)
        except KeyError as ke:
            logger.info("'STEAM_WEB_API_KEY' environment variable not set, "
                        "some features are not available")
            logger.debug(ke)
            cls._instances[cls] = super().__call__(*args, dummy=True, **kwargs)
        except requests.exceptions.HTTPError as e:
            logger.debug(e, exc_info=True)
            logger.warning("unable to initialize Steam Web API, "
                           "some features are not available")
            cls._instances[cls] = super().__call__(*args, dummy=True, **kwargs)
        return cls._instances[cls]

# TODO: dummy, remove!
class WebAPI:
    pass

class SteamWebAPI(WebAPI, metaclass=Singleton):
    """Helper class for using Steam Web API quickly."""

    _REQUESTS_MADE = 0

    @property
    def requests_made(self) -> int:
        """Return the number of requests made to Steam API."""
        return self._REQUESTS_MADE

    def __init__(self, *args, dummy=False, **kwargs):
        self._dummy = dummy
        if not dummy:
            super().__init__(*args, **kwargs)

    @cached(cache=_ttl_cache)
    def get_persona_name(self, steam_id: SteamID) -> str:
        # TODO: Refer to variable in docstring.
        """Return persona name for Steam ID.
        Use get_persona_names for multiple requests to limit
        the number of requests made to Steam API.
        """
        if self._dummy:
            return ""

        # noinspection PyUnresolvedReferences
        response = self.ISteamUser.GetPlayerSummaries(
            steamids=steam_id.as_64)["response"]
        ret = response["players"][0]["personaname"]
        SteamWebAPI._REQUESTS_MADE += 1
        return ret

    def get_persona_names(
            self,
            steam_ids: List[SteamID],
        ) -> Dict[SteamID, str]:
        """Return dictionary of Steam IDs to persona names
        for given Steam IDs. Queries the Steam Web API in
        batches of 100 Steam IDs.
        """
        if self._dummy:
            return {steam_id: "" for steam_id in steam_ids}

        ret = {}

        for steam_id in steam_ids:
            try:
                personaname = _ttl_cache[steam_id]
                ret[steam_id] = personaname
            except KeyError:
                pass

        new_ids = [steam_id for steam_id in steam_ids
                   if steam_id not in ret]

        for chunk in _chunks(new_ids, n=100):
            chunk_ids = [str(cid.as_64)
                         for cid in chunk
                         if cid not in ret]
            chunk_ids_str = ",".join(chunk_ids)

            # noinspection PyUnresolvedReferences
            resp = self.ISteamUser.GetPlayerSummaries(
                steamids=chunk_ids_str)["response"]["players"]
            SteamWebAPI._REQUESTS_MADE += 1

            for r in resp:
                steam_id = SteamID(r["steamid"])
                personaname = r["personaname"]
                ret[steam_id] = personaname
                _ttl_cache[steam_id] = personaname

            input_len = len(chunk_ids)
            output_len = len(ret)
            num_bad = int(abs(input_len - output_len))
            if input_len != output_len:
                logger.warn(
                    f"Steam API did not return valid value "
                    f"for {num_bad} input Steam IDs "
                    f"(input_len={input_len}, output_len={output_len})")

        return ret
