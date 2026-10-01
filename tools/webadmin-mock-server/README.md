# RS2 WebAdmin Mock Server

This is a seeded, in-memory Sanic mock for rs2wapy development and tests. It
is a development-only rs2wapy dependency and is not included in rs2wapy
distributions.

## Development

From this directory:

```bash
uv python install 3.14
uv sync --all-groups --python 3.14
uv run webadmin-mock-server --debug-panel
```

The mock listens on `http://127.0.0.1:8081`. Its optional non-WebAdmin debug
panel is available at `http://127.0.0.1:8081/__debug__/`.

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
