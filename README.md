# rs2wapy

### Rising Storm 2: Vietnam WebAdmin Python Interface
Provides a Python interface for performing RS2 WebAdmin
tasks programmatically.

**Work in progress; interface will change!**

Follow development at https://discord.gg/6tgWHpM


### Examples

##### Quickstart
```python
from rs2wapy import RS2WebAdmin

wa = RS2WebAdmin(
    username="AutoModerator",
    password="topsecret123",
    webadmin_url="http://localhost:8080/",
)
```

##### Poll server ranked status and switch map automatically.
```python
while True:
    if not wa.get_current_game().ranked:
        wa.post_chat_message("Unranked bug happened! Changing map in 5 seconds!")
        time.sleep(5)
        wa.change_map("VNTE-Resort")
    time.sleep(1)
```
