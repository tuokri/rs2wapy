# Rising Storm 2 WebAdmin API Reference

This directory documents the HTTP/WebAdmin behavior implemented by the Rising
Storm 2 server available during this investigation. It is intended to be the
implementation contract for a stateful mock server used by `rs2wapy` tests.

The target is **UnrealEngine IpDrv Web Server build 7258**. The live server is
the compatibility authority: UnrealScript sources are used to find routes and
form fields, but source-only routes are not represented as supported behavior.

## Contents

- [Protocol](protocol.md): base-path behavior, login, cookies, session state,
  request encoding, and response conventions
- [API reference](api-reference.md): route-level behavior grouped by feature
- [Mock contract](contract.yaml): machine-readable endpoint and fixture index
- [Preliminary mock architecture](MOCK_ARCHITECTURE.md): Sanic + Jinja
  compatibility layer and optional HTMX debug-panel boundary
- [Mock implementer guide](MOCK_IMPLEMENTER_GUIDE.md): where to begin building
  the seeded in-memory Sanic mock from this evidence
- [Optional source-data setup](SOURCE_DATA_SETUP.md): one-command setup for
  bundled server assets and user-supplied licensed SDK sources
- [rs2wapy coverage](rs2wapy-coverage.md): async-client operations mapped to
  the mock contract
- [Bundled client assets](bundled-client-assets.md): static template/JavaScript
  evidence and its limits
- [Experimental discovery runbook](EXPERIMENTAL_DISCOVERY_RUNBOOK.md):
  systematic human–LLM procedure for the remaining 95%-confidence evidence
- [Fixtures](fixtures/README.md): normalized evidence captured from the live
  server
- [Development conventions](DEVELOPMENT.md): `uv`, validation, typing, CLI,
  logging, and discovery-safety requirements

## Development

This is a standalone `uv` package nested inside rs2wapy. To prepare its own
environment from this directory, run:

```bash
uv python install 3.14
uv sync --all-groups --python 3.14
```

When rs2wapy's root development environment is synced, this package is also
available there as an editable development-only dependency. It is never part
of a published rs2wapy distribution.

At each development checkpoint, run:

```bash
uv run mypy .
uv run ruff check .
uv run python tools/verify_docs.py
```

All tool CLIs use Click while retaining their established long option names,
environment defaults, and exit behavior. Operational logs use the shared
Loguru configuration and are emitted to the console and the ignored `logs/`
directory; fixtures must remain the only sanitized evidence committed to the
repository.

## Reproducing captures

The synchronous `httpx2` probe in `tools/probe_webadmin.py` never writes
credentials to disk. Supply them through environment variables and write only
sanitized output to `fixtures/`:

```bash
RS2_WEBADMIN_USERNAME=... RS2_WEBADMIN_PASSWORD=... \
uv run python tools/probe_webadmin.py \
    --base-url http://example.invalid:8080 \
    --output fixtures/capture
```

Use `--write-chat` and `--policy-roundtrip` only against an authorized
development server. The policy probe adds then removes one TEST-NET address in
the same authenticated session. The probe records requests and responses,
replacing volatile and sensitive values with placeholders.

`tools/player_action_probe.py` is a separate, controlled moderation probe. It
requires an explicitly named authorized player, mutes then unmutes that player,
submits a session-ban request, and always submits a session-ban revoke followed
by a fresh policy-table check. Use it only when the named player has authorized
the temporary disruption:

```bash
RS2_WEBADMIN_USERNAME=... RS2_WEBADMIN_PASSWORD=... \
uv run python tools/player_action_probe.py \
    --base-url http://example.invalid:8080/ServerAdmin/ \
    --player-name controlled-player \
    --output fixtures/player-actions
```

Add `--permanent-ban-roundtrip` only for a player who explicitly authorizes a
temporary ID ban and reconnection. It sends `banid` and performs the same
immediate revoke/readback cleanup.

For that ban sequence alone, prefer `tools/banid_roundtrip_probe.py`. It
avoids chaining a session-ban before the permanent-ban request, verifies the
active ID-ban row, revokes it in a mandatory cleanup path, and leaves the
human reconnect as a separate explicit checkpoint.

`tools/multiadmin_probe.py` captures the MultiAdmin/SHA-1 profile with a
primary account, an enabled secondary account, and a disabled account. It is
read-only except for login/session creation. `tools/readonly_profile_probe.py`
captures unauthenticated/login boundaries, session isolation, route errors,
and `/data` selectors without changing gameplay or configuration.
`tools/multiadmin_permission_probe.py` temporarily enables a named disposable
restricted account, captures allowed and denied reads, and restores its profile
in a `finally` cleanup path. Use it only with explicit authorization.
`tools/empty_state_probe.py` captures empty-server selectors, safe refreshes,
sorting, and chat polling without sending chat or changing game state.
`tools/phase3_core_probe.py` saves and restores server notes, submits harmless
console commands, and adds then revokes a synthetic short-lived ID ban with
fresh-state verification in each cleanup path. Use it only on an authorized
development server.
`tools/travel_roundtrip_probe.py` refuses to start unless the Current page has
no players, travels to one alternate map, and restores the complete prior
change-map selection. It uses a short remembered login because travel expires
the session-only cookie.
`tools/policy_validation_probe.py` tests only a reserved TEST-NET policy,
including malformed input, duplicate/add/update/delete behavior, and removes
every created row before returning.
`tools/welcome_settings_probe.py` saves a temporary MOTD marker and restores
the complete welcome-screen form, including the browser-derived toggle value.
It uses fresh-page readback rather than server log text as its state authority.
`tools/console_log_probe.py` submits only `help`, `status`, and `version` so
their response pages can be correlated with an operator-provided server log.
No raw logs are captured into the repository.

For the full kick then permanent-ID-ban lifecycle, use
`tools/kick_ban_probe.py`. It pauses for reconnection between the kick and ban,
uses `__ExpUnit=Never`, revokes the resulting ID-ban immediately, and confirms
another reconnect. It is only appropriate for an explicitly authorized player.

The active-discovery resume point is recorded at the top of
`EXPERIMENTAL_DISCOVERY_RUNBOOK.md`. In particular, do not treat every action
shown by the player page as safe or implemented: the browser's
`/current/players/data` path sends unrecognised extended actions to a legacy
handler that falls through to kicking the target.

Validate committed captures with:

```bash
uv run python tools/verify_docs.py
```

## Evidence states

- `live-verified`: the documented request and response were observed against
  the baseline server
- `prerequisite-unavailable`: the route exists, but a required condition such
  as a connected controlled player was unavailable
- `live-verified-denied`: the request was sent, and the server verified a
  documented authorization or state guard without making the requested change
- `not-exposed`: visible in supplied SDK sources but not exposed by the target

Fixtures use `{{UPPER_SNAKE_CASE}}` placeholders. They are examples of wire
shape, not reusable credentials or server state.
