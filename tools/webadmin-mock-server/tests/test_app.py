# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
@pytest.mark.parametrize("action", ("edit-player", "remove-player", "move-team"))
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
async def test_debug_add_player_creates_runtime_player() -> None:
    server = create_mock_server(enable_debug_panel=True)

    _, response = await server.app.asgi_client.post(
        "/__debug__/actions/add-player",
        data={
            "player_id": "76561198021283933",
            "name": "Debug player",
            "team": "South",
            "generate_id": "on",
            "generate_name": "on",
            "connected": "on",
            "is_admin": "on",
        },
    )

    assert response.status == 200
    assert "Added player Debug player" in response.text
    assert "Debug player" in response.text
    snapshot = server.debug.snapshot()
    assert len(snapshot.players) == 1
    assert snapshot.players[0].player_id == "76561198021283933"
    assert snapshot.players[0].name == "Debug player"
    assert snapshot.players[0].team == "South"
    assert snapshot.players[0].is_admin is True
    assert snapshot.players[0].connected is True
    assert snapshot.players[0].unique_id == "0x0110000103A3105D"
    assert snapshot.players[0].identity_kind == "steam"


@pytest.mark.anyio
async def test_debug_add_player_generates_steam_identity_and_bot_name() -> None:
    server = create_mock_server(enable_debug_panel=True)

    _, response = await server.app.asgi_client.post(
        "/__debug__/actions/add-player",
        data={
            "identity_kind": "steam",
            "team": "North",
            "generate_id": "on",
            "generate_name": "on",
            "is_bot": "on",
        },
    )

    assert response.status == 200
    player = server.debug.snapshot().players[0]
    assert player.player_id.isdecimal()
    assert 76_561_197_960_265_728 <= int(player.player_id) < 76_561_202_255_233_024
    assert player.unique_id == f"0x{int(player.player_id):016X}"
    assert player.identity_kind == "steam"
    assert player.name.startswith("BOT ")
    assert player.name.count("BOT ") == 1


@pytest.mark.anyio
async def test_debug_add_player_generates_egs_identity_and_forces_one_bot_prefix() -> None:
    server = create_mock_server(enable_debug_panel=True)

    _, response = await server.app.asgi_client.post(
        "/__debug__/actions/add-player",
        data={
            "identity_kind": "egs",
            "name": "BOT xX Quiet Fox #42",
            "team": "South",
            "generate_id": "on",
            "is_bot": "on",
        },
    )

    assert response.status == 200
    player = server.debug.snapshot().players[0]
    assert 100_000 <= int(player.player_id) <= 1_999_999
    assert player.unique_id == f"mock-egs-{player.player_id}"
    assert player.identity_kind == "egs"
    assert player.name == "BOT xX Quiet Fox #42"


@pytest.mark.anyio
async def test_debug_add_player_rejects_duplicate_player_ids() -> None:
    seed = MockSeed(players=(PlayerSeed("player-1", "unique-1", "Seeded player"),))
    server = create_mock_server(seed, enable_debug_panel=True)

    _, response = await server.app.asgi_client.post(
        "/__debug__/actions/add-player",
        data={"player_id": "player-1", "name": "Duplicate player", "team": "North"},
    )

    assert response.status == 422
    assert "already exists" in response.text
    snapshot = server.debug.snapshot()
    assert len(snapshot.players) == 1
    assert snapshot.players[0].name == "Seeded player"


def test_debug_controller_adds_runtime_players() -> None:
    server = create_mock_server()

    server.debug.add_player(PlayerSeed("player-1", "unique-1", "Joined player", team="North"))

    snapshot = server.debug.snapshot()
    assert len(snapshot.players) == 1
    assert snapshot.players[0].name == "Joined player"


@pytest.mark.anyio
async def test_request_inspector_uses_paths_without_query_data() -> None:
    server = create_mock_server(enable_debug_panel=True)

    _, debug_response = await server.app.asgi_client.get("/__debug__/players")
    _, route_response = await server.app.asgi_client.get("/ServerAdmin/current?credential=private")
    _, inspector_response = await server.app.asgi_client.get("/__debug__/requests")

    assert debug_response.status == 200
    assert route_response.status == 501
    assert inspector_response.status == 200
    assert "/ServerAdmin/current" in inspector_response.text
    assert "credential=private" not in inspector_response.text
    assert "response-status-2xx" in inspector_response.text
    assert "response-status-5xx" in inspector_response.text
    assert server.debug.snapshot().request_records[1].path == "/ServerAdmin/current"


def test_seed_is_copied_into_independent_runtime_state() -> None:
    seed = MockSeed(players=(PlayerSeed("player-1", "unique-1", "Test player"),))
    first = create_mock_server(seed)
    second = create_mock_server(seed)

    first_player = first.debug.snapshot().players[0]
    second_player = second.debug.snapshot().players[0]

    assert first_player is not second_player
    assert first_player == second_player
