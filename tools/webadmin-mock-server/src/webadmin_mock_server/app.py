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

from webadmin_mock_server.generators import PlayerIdentityKind
from webadmin_mock_server.generators import bot_name
from webadmin_mock_server.generators import generate_player_id
from webadmin_mock_server.generators import generate_player_name
from webadmin_mock_server.generators import unique_id_for_player_id
from webadmin_mock_server.models import MockDebugController
from webadmin_mock_server.models import MockSeed
from webadmin_mock_server.models import MockServer
from webadmin_mock_server.models import MockState
from webadmin_mock_server.models import PlayerSeed

PACKAGE_DIRECTORY = Path(__file__).resolve().parent
TEMPLATES_DIRECTORY = PACKAGE_DIRECTORY / "templates"
STATIC_DIRECTORY = PACKAGE_DIRECTORY / "static"
WEBADMIN_BASE_PATH = "/ServerAdmin/"
DEBUG_BASE_PATH = "/__debug__/"

_templates = Environment(
    loader=FileSystemLoader(TEMPLATES_DIRECTORY),
    autoescape=select_autoescape(("html", "xml", "jinja")),
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
        "compat/not_implemented.jinja",
        status=501,
        endpoint_id=endpoint_id,
        request_method=request.method,
    )
    return _record_response(request, response, started_at)


def _form_value(request: Request, name: str) -> str:
    """Return one stripped scalar form value without retaining submitted data."""
    form = request.form
    if form is None:
        return ""
    value = form.get(name)
    return value.strip() if isinstance(value, str) else ""


def _form_has_value(request: Request, name: str) -> bool:
    """Return whether a submitted form contains one named value."""
    form = request.form
    return form is not None and name in form


def _identity_kind_from_request(request: Request) -> PlayerIdentityKind:
    """Read and validate the selected external account-ID family."""
    identity_kind = _form_value(request, "identity_kind") or "steam"
    if identity_kind == "steam":
        return "steam"
    if identity_kind == "egs":
        return "egs"
    raise ValueError("Player ID type must be Steam or EGS")


def _added_player_from_request(request: Request, state: MockState) -> PlayerSeed:
    """Create a safe runtime player from the debug panel's add-player form."""
    player_id = _form_value(request, "player_id")
    name = _form_value(request, "name")
    team = _form_value(request, "team")
    identity_kind = _identity_kind_from_request(request)
    if not player_id and _form_has_value(request, "generate_id"):
        player_id = generate_player_id(identity_kind, set(state.players))
    if not name and _form_has_value(request, "generate_name"):
        name = generate_player_name()
    if not player_id or not name or not team:
        raise ValueError("Player ID, player name, and team are required")
    if player_id in state.players:
        raise ValueError("A player with that player ID already exists")
    is_bot = _form_has_value(request, "is_bot")
    if is_bot:
        name = bot_name(name)
    return PlayerSeed(
        player_id=player_id,
        unique_id=unique_id_for_player_id(player_id, identity_kind),
        name=name,
        team=team,
        is_admin=_form_has_value(request, "is_admin"),
        is_bot=is_bot,
        connected=_form_has_value(request, "connected"),
        identity_kind=identity_kind,
    )


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
                    "identity_kind": player.identity_kind,
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
                "debug/dashboard.jinja", context=_debug_context(request, "dashboard")
            )
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}players")
        async def debug_players(request: Request) -> HTTPResponse:
            """Render seeded players and available debug controls."""
            started_at = monotonic()
            response = _render("debug/players.jinja", context=_debug_context(request, "players"))
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}state")
        async def debug_state(request: Request) -> HTTPResponse:
            """Render a safe projection of the currently modelled runtime state."""
            started_at = monotonic()
            response = _render("debug/state.jinja", context=_debug_context(request, "state"))
            return _record_response(request, response, started_at)

        @app.get(f"{DEBUG_BASE_PATH}requests")
        async def debug_requests(request: Request) -> HTTPResponse:
            """Render bounded sanitized request metadata."""
            started_at = monotonic()
            response = _render("debug/requests.jinja", context=_debug_context(request, "requests"))
            return _record_response(request, response, started_at)

        @app.post(f"{DEBUG_BASE_PATH}actions/<action_name:str>")
        async def debug_action(request: Request, action_name: str) -> HTTPResponse:
            """Run the implemented debug actions or report a draft action."""
            started_at = monotonic()
            state: MockState = request.app.ctx.mock_state
            if action_name == "add-player":
                try:
                    player = _added_player_from_request(request, state)
                    state.add_player(player)
                except ValueError as error:
                    response = _render(
                        "debug/components/player_runtime.jinja",
                        status=422,
                        players=state.snapshot().players,
                        action_message=str(error),
                        action_state="error",
                        debug_base_path=DEBUG_BASE_PATH,
                        oob_response=True,
                    )
                else:
                    response = _render(
                        "debug/components/player_runtime.jinja",
                        players=state.snapshot().players,
                        action_message=f"Added player {player.name}",
                        action_state="success",
                        debug_base_path=DEBUG_BASE_PATH,
                        oob_response=True,
                    )
                return _record_response(request, response, started_at)

            allowed_actions = {"edit-player", "remove-player", "move-team"}
            if action_name not in allowed_actions:
                response = _render(
                    "debug/components/not_implemented.jinja",
                    action_name="unknown debug action",
                )
                return _record_response(request, response, started_at)
            response = _render(
                "debug/components/not_implemented.jinja",
                action_name=action_name.replace("-", " "),
            )
            return _record_response(request, response, started_at)

    return MockServer(app=app, debug=MockDebugController(state))
