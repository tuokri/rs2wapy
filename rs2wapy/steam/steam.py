import os
import sys
from typing import Dict
from typing import Sequence

import requests
import steam
from logbook import Logger
from logbook import StreamHandler

StreamHandler(sys.stdout, level="WARNING", bubble=True).push_application()
logger = Logger(__name__)


class Singleton(type):
    _instances = {}

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


class SteamWebAPI(steam.webapi.WebAPI, metaclass=Singleton):
    """Helper class for using Steam Web API quickly.

    API request return values are not cached at this time,
    but will be cached in future revisions.
    """

    _REQUESTS_MADE = 0

    @property
    def requests_made(self) -> int:
        """Return the number of requests made to Steam API."""
        return self._REQUESTS_MADE

    # TODO: Cache results.
    def __init__(self, *args, dummy=False, **kwargs):
        self._dummy = dummy
        if not dummy:
            super().__init__(*args, **kwargs)

    def get_persona_name(self, steam_id: steam.SteamID) -> str:
        # TODO: Refer to variable in docstring.
        """Return persona name for Steam ID.
        Use get_persona_names for multiple requests to limit
        the number of made to Steam API.
        """
        if self._dummy:
            return ""
        else:
            ret = self.ISteamUser.GetPlayerSummaries(
                steamids=steam_id.as_64)["response"]["players"][0]["personaname"]
            SteamWebAPI._REQUESTS_MADE += 1
            return ret

    def get_persona_names(self, steam_ids: Sequence[steam.SteamID]
                          ) -> Dict[steam.SteamID, str]:
        """Return dictionary of Steam IDs to persona names
        for given Steam IDs. Current limited to a maximum
        of 100 IDs per request.
        """
        if self._dummy:
            return {steam_id: "" for steam_id in steam_ids}

        # TODO: handle more than 100 IDs.
        if len(steam_ids) > 100:
            raise NotImplementedError(
                "TODO: May request only 100 players at a time!")

        steam_ids = [str(sid.as_64) for sid in steam_ids]
        steam_ids = ",".join(steam_ids)

        resp = self.ISteamUser.GetPlayerSummaries(
            steamids=steam_ids)["response"]["players"]
        SteamWebAPI._REQUESTS_MADE += 1

        return {
            steam.SteamID(r["steamid"]): r["personaname"] for r in resp
        }
