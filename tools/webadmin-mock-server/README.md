# RS2 WebAdmin Mock Server

This is a seeded, in-memory Sanic mock for rs2wapy development and tests. It
is a development-only rs2wapy dependency. It is excluded from the rs2wapy
wheel and included in the rs2wapy source distribution.

## Development

From this directory:

```bash
uv python install 3.14
uv sync --all-groups --python 3.14
uv run webadmin-mock-server --debug-panel
```

The mock listens on `http://127.0.0.1:8081`. Its optional non-WebAdmin debug
panel is available at `http://127.0.0.1:8081/__debug__/`. Sanic access logging
is enabled by default. Add `--reload` during local mock development to restart
the server when its source changes:

```bash
uv run webadmin-mock-server --debug-panel --reload
```

## Debug panel design

The optional debug panel is a dark-only, CSS-only modern reinterpretation of
RS2 WebAdmin's cinematic banner, distressed charcoal panels, high-contrast
navigation, and red action cues. It uses original styles rather than bundled
RS2 art, logos, stylesheets, or remote font and asset requests. The debug panel
is not a WebAdmin compatibility surface; its visual language and routes can
evolve independently of `/ServerAdmin/` fidelity work.

The player-add flow is implemented. Its edit, move-team, and remove controls
remain visibly labelled no-op drafts until their matching typed control-plane
operations are implemented.

For rs2wapy tests, create a seeded app through `create_mock_server()` and pass
`server.app` to a Sanic test client or test fixture. Starting another mock
server from the same seed always creates a fresh independent runtime state.

```python
from webadmin_mock_server import MockSeed
from webadmin_mock_server import PlayerSeed
from webadmin_mock_server import create_mock_server

server = create_mock_server(
    MockSeed(players=(PlayerSeed("player-1", "unique-1", "Example"),)),
    enable_debug_panel=True,
)
```

The optional debug panel can add a player after startup. It can generate a
SteamID64 (and matching UE3 hexadecimal unique ID) or a synthetic EGS-like
numeric ID, plus a compact multiplayer-style username. EGS IDs are synthetic:
the SDK does not disclose Tripwire's private allocation algorithm. Select Bot
to force one `BOT ` prefix onto the resulting name. Every runtime-only player
disappears when the mock server is recreated.

Generated usernames intentionally vary between compact handles, multi-word
names, and common player-name punctuation such as `_`, `-`, `#`, and `!`.

Run the package checks with:

```bash
uv run mypy .
uv run ruff check .
uv run pytest
```

## HTMX vendor update

The debug panel vendors readable, unminified HTMX at
`src/webadmin_mock_server/static/debug/vendor/htmx/`. Do not replace it with a
CDN reference, a minified duplicate, or a Git submodule.

To upgrade it, download `dist/htmx.js` and `LICENSE` from the reviewed upstream
release, replace the two local files, update the version, source URLs, and
SHA-256 digests in `MANIFEST.toml`, then run `uv run pytest tests/test_vendor.py`.
Commit the asset, license, and manifest together.
