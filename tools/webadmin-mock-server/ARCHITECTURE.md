# Mock boilerplate architecture

## State boundary

`PlayerSeed` and `MockSeed` are frozen test-fixture input. The application
factory copies them into mutable runtime `Player` objects stored in private
`MockState`. This guarantees that a test's runtime state cannot mutate a
fixture used to create another server.

```python
server = create_mock_server(MockSeed(players=(PlayerSeed(...),)))
app = server.app
snapshot = server.debug.snapshot()
```

`server.debug` is the typed control-plane boundary for simulating external
gameplay events. It currently provides `add_player(PlayerSeed(...))`, which
simulates a post-seed player join. Future debug-panel controls and
WebAdmin-compatible route handlers must share the same state/domain operations.

## Compatibility boundary

The only selected compatibility families are `/ServerAdmin/`,
`/ServerAdmin/current`, and `/ServerAdmin/current/players`. They render a
generic Jinja `501` page and perform no authentication, parsing, or mutation.
All other WebAdmin paths are normal `404`s until live-verified behavior is
implemented from the API documentation and fixtures.

The `/` redirect is transport plumbing only. It directs browsers to
`/ServerAdmin/` and does not emulate a WebAdmin feature.

## Debug panel

`/__debug__/` is opt-in and is never a WebAdmin compatibility route. It renders
the seeded dashboard, player table, safe state projection, and bounded request
metadata. Request telemetry shows paths but intentionally omits cookies, tokens,
credentials, raw headers, query data, and request bodies.

The dark-only panel is a modern, CSS-only reinterpretation of RS2 WebAdmin's
cinematic banner, distressed charcoal surfaces, pale section strips, red action
cues, and semantic North/South team colours. It does not copy or distribute RS2
images, logos, stylesheets, or external font/asset requests. Its no-op controls
are visibly labelled as drafts. Responsive layouts, visible keyboard focus, and
reduced-motion support are required panel behavior.

The Add player form uses HTMX to create a player in the in-memory runtime state
and replace the player table partial. It accepts a manually supplied identity
or generates one at submit time. Steam generation produces a public individual
SteamID64 and follows the SDK's `SteamId64ToUniqueId` conversion: the same
64-bit integer formatted as `0x` plus 16 uppercase hexadecimal digits. EGS
generation creates a deliberately synthetic six- or seven-digit number in the
range observed on live servers. The SDK exposes no Tripwire EGS allocation
algorithm, so the mock stores its distinct `mock-egs-<number>` projection rather
than claim it is a real Epic identifier. Generated names are intentionally
allowed to use spaces and common player-name punctuation. Bot creation always
normalizes the resulting runtime name to exactly one `BOT ` prefix. Edit,
move-team, and remove remain no-op draft controls.

## Deferred work

- login, cookies, sessions, and legacy response shells;
- stateful WebAdmin route behavior from `webadmin-api-docs/contract.yaml`;
- control-plane player remove/connect/team operations;
- debug-panel write actions beyond add-player, bans, policies, chats, and session inspectors.
