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
        yield seq[i : i + n]


class Singleton(type):
    _instances: dict[type, Singleton] = {}

    def __call__(cls, *args, **kwargs) -> Singleton:
        try:
            steam_api_key = os.environ["STEAM_WEB_API_KEY"]
            if cls not in cls._instances:
                instance = super().__call__(
                    steam_api_key=steam_api_key, *args, **kwargs
                )
                cls._instances[cls] = instance
        except KeyError as ke:
            logger.info(
                "'STEAM_WEB_API_KEY' environment variable not set, "
                "some features are not available"
            )
            logger.debug(ke)
            instance = super().__call__(*args, dummy=True, **kwargs)
            cls._instances[cls] = instance
        except httpx2.HTTPError as e:
            logger.debug(e.__name__, exc_info=True)
            logger.warning(
                "unable to initialize Steam Web API, some features are not available"
            )
            instance = super().__call__(*args, dummy=True, **kwargs)
            cls._instances[cls] = instance

        return cls._instances[cls]


class SteamWebAPI(metaclass=Singleton):
    """Helper class for using Steam Web API quickly."""

    _REQUESTS_MADE = 0

    @property
    def requests_made(self) -> int:
        """Return the number of requests made to Steam API."""
        return self._REQUESTS_MADE

    def __init__(
        self,
        steam_api_key: str | None = None,
        dummy: bool = False,
    ):
        # TODO: refactor dummy outta here!
        # TODO: maybe allow timeout configuration etc.

        self._client: httpx2.AsyncClient
        self._api_key = steam_api_key

        self._dummy = dummy
        if not dummy:
            self._client = httpx2.AsyncClient()

    @cached(cache=_ttl_cache)
    async def get_persona_name(self, steam_id: SteamID) -> str:
        # TODO: Refer to variable in docstring.
        """Return persona name for Steam ID.
        Use get_persona_names for multiple requests to limit
        the number of requests made to Steam API.
        """
        if self._dummy:
            return ""

        response = await self._client.get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
            params={
                "key": self._api_key,
                "steamids": steam_id.as_64,
            },
        )
        resp_json = response.json()

        ret = ""
        players = resp_json["response"]["players"]
        if players:
            ret = players[0]["personaname"]

        SteamWebAPI._REQUESTS_MADE += 1
        return ret

    async def get_persona_names(
        self,
        steam_ids: list[SteamID],
    ) -> dict[SteamID, str]:
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

        new_ids = [steam_id for steam_id in steam_ids if steam_id not in ret]

        for chunk in _chunks(new_ids, n=100):
            chunk_ids = [str(cid.as_64) for cid in chunk if cid not in ret]
            chunk_ids_str = ",".join(chunk_ids)

            resp = await self._client.get(
                "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
                params={
                    "key": self._api_key,
                    "steamids": chunk_ids_str,
                },
            )
            resp_players = resp.json()["response"]["players"]

            SteamWebAPI._REQUESTS_MADE += 1

            for r in resp_players:
                steam_id = SteamID(r["steamid"])
                personaname = r["personaname"]
                ret[steam_id] = personaname
                _ttl_cache[steam_id] = personaname

            input_len = len(chunk_ids)
            output_len = len(ret)
            num_bad = int(abs(input_len - output_len))
            if input_len != output_len:
                logger.warning(
                    "Steam API did not return valid value "
                    "for {} input Steam IDs "
                    "(input_len={}, output_len={})",
                    num_bad,
                    input_len,
                    output_len,
                )

        return ret
