"""Typed fixture input and runtime entities for the mock server."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from time import monotonic

from sanic import Sanic


@dataclass(frozen=True, slots=True)
class PlayerSeed:
    """Immutable input used to create one live player for a new mock server."""

    player_id: str
    unique_id: str
    name: str
    team: str = "Spectator"
    is_admin: bool = False
    is_bot: bool = False
    connected: bool = True


@dataclass(slots=True)
class Player:
    """Mutable live player state for one mock-server lifetime."""

    player_id: str
    unique_id: str
    name: str
    team: str
    is_admin: bool
    is_bot: bool
    connected: bool

    @classmethod
    def from_seed(cls, seed: PlayerSeed) -> Player:
        """Copy immutable fixture data into one mutable runtime player."""
        return cls(
            player_id=seed.player_id,
            unique_id=seed.unique_id,
            name=seed.name,
            team=seed.team,
            is_admin=seed.is_admin,
            is_bot=seed.is_bot,
            connected=seed.connected,
        )


@dataclass(frozen=True, slots=True)
class MockSeed:
    """Immutable input snapshot used to initialize one mock server."""

    server_name: str = "RS2 WebAdmin Mock"
    map_name: str = "VNTE-Unknown"
    game_type: str = "ROGame.ROGameInfoTerritories"
    players: tuple[PlayerSeed, ...] = ()


@dataclass(frozen=True, slots=True)
class RequestRecord:
    """Sanitized request metadata displayed by the development-only inspector."""

    endpoint_id: str
    method: str
    status: int
    duration_ms: float


@dataclass(frozen=True, slots=True)
class MockStateSnapshot:
    """Read-only state projection exposed through the test-side debug handle."""

    server_name: str
    map_name: str
    game_type: str
    players: tuple[Player, ...]
    request_records: tuple[RequestRecord, ...]


class MockState:
    """Private mutable state discarded when the mock application is recreated."""

    def __init__(self, seed: MockSeed) -> None:
        self.server_name = seed.server_name
        self.map_name = seed.map_name
        self.game_type = seed.game_type
        self.players = {player.player_id: Player.from_seed(player) for player in seed.players}
        self.request_records: deque[RequestRecord] = deque(maxlen=50)

    def snapshot(self) -> MockStateSnapshot:
        """Return a detached, stable projection suitable for test assertions."""
        players = tuple(
            Player(
                player_id=player.player_id,
                unique_id=player.unique_id,
                name=player.name,
                team=player.team,
                is_admin=player.is_admin,
                is_bot=player.is_bot,
                connected=player.connected,
            )
            for player in self.players.values()
        )
        return MockStateSnapshot(
            server_name=self.server_name,
            map_name=self.map_name,
            game_type=self.game_type,
            players=players,
            request_records=tuple(self.request_records),
        )

    def record_request(self, endpoint_id: str, method: str, status: int, started_at: float) -> None:
        """Store only safe request metadata for the debug-panel inspector."""
        duration_ms = (monotonic() - started_at) * 1000
        self.request_records.append(
            RequestRecord(endpoint_id, method, status, round(duration_ms, 2))
        )


@dataclass(frozen=True, slots=True)
class MockDebugController:
    """Read-only test-side control-plane placeholder for future external events."""

    _state: MockState

    def snapshot(self) -> MockStateSnapshot:
        """Expose a detached state view without allowing direct mutation."""
        return self._state.snapshot()


@dataclass(frozen=True, slots=True)
class MockServer:
    """Application and test-side debug handle returned by the factory."""

    app: Sanic
    debug: MockDebugController
