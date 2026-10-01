"""Sanic application factory and deliberately incomplete route surface."""

from __future__ import annotations

from pathlib import Path
from time import monotonic
from uuid import uuid4

from jinja2 import Environment
from jinja2 import FileSystemLoader
from jinja2 import select_autoescape
from sanic import Request
from sanic import Sanic
from sanic.response import HTTPResponse
from sanic.response import html
from sanic.response import redirect

from webadmin_mock_server.models import MockDebugController
from webadmin_mock_server.models import MockSeed
from webadmin_mock_server.models import MockServer
from webadmin_mock_server.models import MockState

PACKAGE_DIRECTORY = Path(__file__).resolve().parent
TEMPLATES_DIRECTORY = PACKAGE_DIRECTORY / "templates"
STATIC_DIRECTORY = PACKAGE_DIRECTORY / "static"
WEBADMIN_BASE_PATH = "/ServerAdmin/"
DEBUG_BASE_PATH = "/__debug__/"

_templates = Environment(
    loader=FileSystemLoader(TEMPLATES_DIRECTORY),
    autoescape=select_autoescape(("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _render(
    template_name: str,
    *,
    status: int = 200,
    context: dict[str, object] | None = None,
    **template_values: object,
) -> HTTPResponse:
    """Render one Jinja template with the expected HTML content type."""
    template = _templates.get_template(template_name)
    return html(template.render(**(context or {}), **template_values), status=status)


def _record_response(
    request: Request,
    response: HTTPResponse,
    started_at: float,
) -> HTTPResponse:
    """Record safe metadata without preserving request data or credentials."""
    state: MockState = request.app.ctx.mock_state
    state.record_request(request.path, request.method, response.status, started_at)
    return response


def _not_implemented(request: Request, endpoint_id: str) -> HTTPResponse:
    """Return a clear non-compatibility response for a selected route stub."""
    started_at = monotonic()
    response = _render(
        "compat/not_implemented.html",
        status=501,
        endpoint_id=endpoint_id,
        request_method=request.method,
    )
    return _record_response(request, response, started_at)


def _debug_context(request: Request, page: str) -> dict[str, object]:
    """Build safe, read-only context for a debug-panel page."""
    state: MockState = request.app.ctx.mock_state
    snapshot = state.snapshot()
    return {
        "active_page": page,
        "debug_base_path": DEBUG_BASE_PATH,
        "server": {
            "name": snapshot.server_name,
            "map_name": snapshot.map_name,
            "game_type": snapshot.game_type,
        },
        "players": snapshot.players,
        "request_records": tuple(reversed(snapshot.request_records)),
        "state_view": {
            "server_name": snapshot.server_name,
            "map_name": snapshot.map_name,
            "game_type": snapshot.game_type,
            "players": [
                {
                    "player_id": player.player_id,
                    "name": player.name,
                    "team": player.team,
                    "is_admin": player.is_admin,
                    "is_bot": player.is_bot,
                    "connected": player.connected,
                }
                for player in snapshot.players
            ],
        },
    }


def create_mock_server(
    seed: MockSeed | None = None,
    *,
    enable_debug_panel: bool = False,
    app_name: str | None = None,
) -> MockServer:
    """Create a fresh seeded mock server with no persistence between instances."""
    state = MockState(seed or MockSeed())
    app = Sanic(app_name or f"rs2_webadmin_mock_{uuid4().hex}", configure_logging=False)
    app.config.ACCESS_LOG = True
    app.ctx.mock_state = state

    @app.get("/")
    async def root_redirect(_request: Request) -> HTTPResponse:
        """Provide only the documented path redirect as transport plumbing."""
        return redirect(WEBADMIN_BASE_PATH, status=302)

    @app.route(WEBADMIN_BASE_PATH, methods=("GET", "POST"))
    async def app_root(request: Request) -> HTTPResponse:
        """Stub the WebAdmin landing and login route."""
        return _not_implemented(request, "app-root")

    @app.route(f"{WEBADMIN_BASE_PATH}current", methods=("GET", "POST"))
    async def current(request: Request) -> HTTPResponse:
        """Stub the documented Current route family."""
        return _not_implemented(request, "current")

    @app.route(f"{WEBADMIN_BASE_PATH}current/players", methods=("GET", "POST"))
    async def current_players(request: Request) -> HTTPResponse:
        """Stub the documented Current Players route family."""
        return _not_implemented(request, "players")

    if enable_debug_panel:
        app.static(f"{DEBUG_BASE_PATH}static", str(STATIC_DIRECTORY / "debug"), name="debug-static")

        @app.get(DEBUG_BASE_PATH)
        async def debug_dashboard(request: Request) -> HTTPResponse:
            """Render a read-only summary of the seeded mock state."""
            started_at = monotonic()
            response = _render(
                "debug/dashboard.html", context=_debug_context(request, "dashboard")
            )
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}players")
        async def debug_players(request: Request) -> HTTPResponse:
            """Render seeded players and intentionally unavailable controls."""
            started_at = monotonic()
            response = _render("debug/players.html", context=_debug_context(request, "players"))
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}state")
        async def debug_state(request: Request) -> HTTPResponse:
            """Render a safe projection of currently modelled runtime state."""
            started_at = monotonic()
            response = _render("debug/state.html", context=_debug_context(request, "state"))
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}requests")
        async def debug_requests(request: Request) -> HTTPResponse:
            """Render bounded sanitized request metadata."""
            started_at = monotonic()
            response = _render("debug/requests.html", context=_debug_context(request, "requests"))
            return _record_response(request, response, started_at)

        @app.post(f"{DEBUG_BASE_PATH}actions/<action_name:str>")
        async def debug_action(request: Request, action_name: str) -> HTTPResponse:
            """Provide an HTMX feedback flow without changing runtime state."""
            started_at = monotonic()
            allowed_actions = {"add-player", "edit-player", "remove-player", "move-team"}
            if action_name not in allowed_actions:
                response = _render(
                    "debug/components/not_implemented.html",
                    action_name="unknown debug action",
                )
                return _record_response(request, response, started_at)
            response = _render(
                "debug/components/not_implemented.html",
                action_name=action_name.replace("-", " "),
            )
            return _record_response(request, response, started_at)

    return MockServer(app=app, debug=MockDebugController(state))
