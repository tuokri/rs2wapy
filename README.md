# rs2wapy

### Rising Storm 2: Vietnam WebAdmin Python Interface
Provides a Python interface for performing RS2 WebAdmin
tasks programmatically.

**Work in progress; interface will change!**

Follow development at https://discord.gg/6tgWHpM


### Brief Usage Examples

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
