import os
import sys

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
            return cls._instances[cls]
        except KeyError as ke:
            logger.info("'STEAM_WEB_API_KEY' environment variable not set, "
                        "some features are not available")
            logger.debug(ke)
        except requests.exceptions.HTTPError as e:
            logger.debug(e, exc_info=True)
            logger.warning("unable to initialize Steam Web API, "
                           "some features are not available")


class SteamWebAPI(steam.webapi.WebAPI, metaclass=Singleton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_persona_name(self, steam_id: steam.SteamID) -> str:
        return self.ISteamUser.GetPlayerSummaries(
            steamids=steam_id.as_64)["response"]["players"][0]["personaname"]
