# rs2wapy
[![Travis](https://travis-ci.com/tuokri/rs2wapy.svg?branch=master)](https://travis-ci.com/github/tuokri/rs2wapy)
[![Maintainability](https://api.codeclimate.com/v1/badges/9d561a84b14c8c3486f6/maintainability)](https://codeclimate.com/github/tuokri/rs2wapy/maintainability)

### Rising Storm 2: Vietnam WebAdmin Python Interface
Provides a Python interface for performing RS2 WebAdmin
tasks programmatically.

The library uses PycURL internally to communicate with RS2 WebAdmin.

**Work in progress; interface will change!**


### Brief Usage Examples
This section contains some brief usage examples.
For more comprehensive tutorials check out the
[examples repository](https://github.com/tuokri/rs2wapy-examples).

##### Installation
```bash
# Requires Python=>3.7
pip install rs2wapy
```

##### Steam Web API key (optional)
Setting your Steam Web API key as an environment variable
allows `rs2wapy` to offer some extra functionality.

Unix:
```bash
export STEAM_WEB_API_KEY="TOPSECRETKEY"
```

Windows:
```Batchfile
set STEAM_WEB_API_KEY="TOPSECRETKEY"
```

##### Quickstart
It is recommended to create a new WebAdmin account for
`rs2wapy`.
```python
from rs2wapy import RS2WebAdmin

wa = RS2WebAdmin(
    username="AutoModerator",
    password="topsecret123",
    webadmin_url="http://localhost:8080/",
)
```

##### Poll server ranked status and switch map automatically
```python
while True:
    if not wa.get_current_game().ranked:
        wa.post_chat_message("Unranked bug happened! Changing map in 5 seconds!")
        time.sleep(5)
        wa.change_map("VNTE-Resort")
    time.sleep(1)
```

##### Forward in-game chat to a Discord webhook with discord.py.
```python
import time

from discord import RequestsWebhookAdapter
from discord import Webhook
from discord.utils import escape_markdown
from discord.utils import escape_mentions

from rs2wapy import RS2WebAdmin
from rs2wapy.models import AllTeam
from rs2wapy.models import BlueTeam
from rs2wapy.models import RedTeam

# Discord webhook info.
webhook = Webhook.partial(
    id=123456,
    token="abcdefg",
    adapter=RequestsWebhookAdapter()
)

# Webadmin credentials.
USERNAME = "Admin"
PASSWORD = "adminpassword"
URL = "http://127.0.0.1:8080/ServerAdmin"

TEAM_TO_EMOJI = {
    BlueTeam: ":blue_square:",
    RedTeam: ":red_square:",
    AllTeam: ":white_square_button:",
}

TEAM_TO_TEAMNAME = {
    BlueTeam: "SOUTH",
    RedTeam: "NORTH",
    AllTeam: "ALL",
}


def get_team_emoji(team):
    try:
        return TEAM_TO_EMOJI[team]
    except KeyError:
        return "?"


def get_team_name(team):
    try:
        return TEAM_TO_TEAMNAME[team]
    except KeyError:
        return "?"


def main():
    webadmin = RS2WebAdmin(USERNAME, PASSWORD, URL)
    messages = []

    while True:
        try:
            messages.extend(webadmin.get_chat_messages())
        except Exception as e:
            print(f"error getting messages: {e}")
            print("attempting to reconnect...")
            webadmin = RS2WebAdmin(USERNAME, PASSWORD, URL)

        if messages:
            for message in messages:
                text = message.text
                sender = message.sender
                team = message.team

                team_name = get_team_name(team)
                team_emoji = get_team_emoji(team)

                # Prevent pinging @everyone from in-game chat
                # and other "funny" stuff.
                text = escape_markdown(text)
                text = escape_mentions(text)
                sender = escape_markdown(sender)
                sender = escape_mentions(sender)

                try:
                    webhook.send(f"**{sender}** [{team_name}] {team_emoji}: {text}")
                except Exception as e:
                    print(f"error sending message: {e}")

        messages = []
        time.sleep(3)
```

The above are just simple examples of how to use the library. In the future,
the library will be able to automate all tasks which RS2 WebAdmin offers.
You can check the status of currently implemented WebAdmin features here:
https://github.com/tuokri/rs2wapy/issues/9.
