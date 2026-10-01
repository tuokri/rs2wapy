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

`server.debug` is deliberately read-only in this boilerplate. It is the future
typed control-plane boundary for simulating external gameplay events such as a
player joining, leaving, or changing team. Future debug-panel controls and
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

The player buttons use HTMX to render a no-op feedback fragment. They do not
change state yet. This establishes layout and partial-response behavior before
the future control plane is implemented.

## Deferred work

- login, cookies, sessions, and legacy response shells;
- stateful WebAdmin route behavior from `webadmin-api-docs/contract.yaml`;
- control-plane player add/remove/connect/team operations;
- debug-panel write actions, bans, policies, chats, and session inspectors.
