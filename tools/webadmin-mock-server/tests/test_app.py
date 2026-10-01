"""Behavior checks for the mock boilerplate boundary."""

from __future__ import annotations

import pytest

from webadmin_mock_server import MockSeed
from webadmin_mock_server import PlayerSeed
from webadmin_mock_server import create_mock_server


@pytest.mark.anyio
async def test_root_redirects_to_webadmin_base_path() -> None:
    server = create_mock_server()

    _, response = await server.app.asgi_client.get("/")

    assert response.status == 302
    assert response.headers["location"] == "/ServerAdmin/"


def test_mock_server_enables_sanic_access_logging() -> None:
    server = create_mock_server()

    assert server.app.config.ACCESS_LOG is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "endpoint_id"),
    (
        ("/ServerAdmin/", "app-root"),
        ("/ServerAdmin/current", "current"),
        ("/ServerAdmin/current/players", "players"),
    ),
)
async def test_selected_webadmin_routes_are_explicit_not_implemented(
    path: str, endpoint_id: str
) -> None:
    server = create_mock_server()

    _, response = await server.app.asgi_client.post(path)

    assert response.status == 501
    assert response.content_type == "text/html; charset=utf-8"
    assert endpoint_id in response.text
    assert "not implemented" in response.text


@pytest.mark.anyio
async def test_unregistered_webadmin_route_is_not_found() -> None:
    server = create_mock_server()

    _, response = await server.app.asgi_client.get("/ServerAdmin/about")

    assert response.status == 404


@pytest.mark.anyio
async def test_debug_panel_is_opt_in() -> None:
    disabled = create_mock_server()
    enabled = create_mock_server(enable_debug_panel=True)

    _, disabled_response = await disabled.app.asgi_client.get("/__debug__/")
    _, enabled_response = await enabled.app.asgi_client.get("/__debug__/")

    assert disabled_response.status == 404
    assert enabled_response.status == 200
    assert "Mock Server Control Panel" in enabled_response.text
    assert "Development only" in enabled_response.text
    assert "http://" not in enabled_response.text
    assert "https://" not in enabled_response.text

    _, disabled_asset = await disabled.app.asgi_client.get("/__debug__/static/vendor/htmx/htmx.js")
    _, enabled_asset = await enabled.app.asgi_client.get("/__debug__/static/vendor/htmx/htmx.js")
    assert disabled_asset.status == 404
    assert enabled_asset.status == 200


@pytest.mark.anyio
async def test_debug_panel_renders_seeded_players_and_redacts_unique_ids() -> None:
    player = PlayerSeed("player-1", "secret-unique-id", "Test player", team="Allies")
    server = create_mock_server(MockSeed(players=(player,)), enable_debug_panel=True)

    _, players_response = await server.app.asgi_client.get("/__debug__/players")
    _, state_response = await server.app.asgi_client.get("/__debug__/state")

    assert players_response.status == 200
    assert "Test player" in players_response.text
    assert "secret-unique-id" not in players_response.text
    assert state_response.status == 200
    assert "secret-unique-id" not in state_response.text


@pytest.mark.anyio
@pytest.mark.parametrize("action", ("add-player", "edit-player", "remove-player", "move-team"))
async def test_debug_actions_are_noop_feedback_flows(action: str) -> None:
    player = PlayerSeed("player-1", "unique-1", "Test player")
    server = create_mock_server(MockSeed(players=(player,)), enable_debug_panel=True)
    before = server.debug.snapshot()

    _, response = await server.app.asgi_client.post(f"/__debug__/actions/{action}")

    assert response.status == 200
    assert "not implemented" in response.text
    assert "Draft action" in response.text
    after = server.debug.snapshot()
    assert after.players == before.players
    assert after.players[0].name == "Test player"


@pytest.mark.anyio
async def test_request_inspector_uses_paths_without_query_data() -> None:
    server = create_mock_server(enable_debug_panel=True)

    _, route_response = await server.app.asgi_client.get("/ServerAdmin/current?credential=private")
    _, inspector_response = await server.app.asgi_client.get("/__debug__/requests")

    assert route_response.status == 501
    assert inspector_response.status == 200
    assert "/ServerAdmin/current" in inspector_response.text
    assert "credential=private" not in inspector_response.text
    assert server.debug.snapshot().request_records[0].path == "/ServerAdmin/current"


def test_seed_is_copied_into_independent_runtime_state() -> None:
    seed = MockSeed(players=(PlayerSeed("player-1", "unique-1", "Test player"),))
    first = create_mock_server(seed)
    second = create_mock_server(seed)

    first_player = first.debug.snapshot().players[0]
    second_player = second.debug.snapshot().players[0]

    assert first_player is not second_player
    assert first_player == second_player
