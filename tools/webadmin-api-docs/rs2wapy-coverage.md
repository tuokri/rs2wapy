# rs2wapy Async Coverage

This matrix targets `make-async-and-modernize` commit
`0ead47173da886996d366362f6bc5cf9867c3e5a`. It tells mock implementers which
HTML structures the client parses and which operations need priority.

| Async public operation                            | Contract routes                                                    | Mock priority | Notes                                                                                                                                                  |
|---------------------------------------------------|--------------------------------------------------------------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `get_current_game`, scoreboards                   | `/current`                                                         | P0            | Preserve current-game info/rules and player/team score tables parsed by `parse_current_game`.                                                          |
| `get_chat_messages`                               | `/current/chat/data`                                               | P0            | Per-session incremental HTML fragments; no JSON.                                                                                                       |
| `post_chat_message`                               | `/current/chat`, `/current/chat/data`                              | P0            | Form fields `ajax`, `message`, `teamsay`; live-verified.                                                                                               |
| `change_map`, `get_maps`, `get_maps_list`         | `/current/change`, `/current/change/data`, `/current/change/check` | P0            | Parse game-type/map `<option>` elements and mutator group count. Model a pending-travel state.                                                         |
| `get_players`, player wrappers                    | `/current/players`                                                 | P0            | Preserve `#players` table, row identity controls, and empty-player variant.                                                                            |
| `kick_player`, `ban_player`, `session_ban_player` | player data / policy routes                                        | P1            | Existing branch has partial/unimplemented paths; mock action XML and live-verified kick, session-ban, ID-ban, revoke, and reconnect state transitions. |
| `get_squads`                                      | `/current/squads`                                                  | P1            | Preserve squad table/forms and empty-squad variant.                                                                                                    |
| access-policy operations                          | `/policy`                                                          | P1            | Adapter implementation is incomplete, but add/delete form behavior is live-verified.                                                                   |
| `get_banned_players`                              | `/policy/bans`                                                     | P1            | Preserve the full active-ban table; build 7258 exposes no hidden paging index or paging controls in the 50/1000-row synthetic passes. |
| `get_session_banned_players`                      | `/policy/session`                                                  | P1            | Preserve session-ban table and revoke controls.                                                                                                        |
| `get_tracked_players`                             | `/policy/tracking`                                               | P1            | Preserve tab/pagination inputs such as `__FirstVisibleRowIndex`; live-verified 25-row pages and 1000-row clamping behavior. |
| `get_members`                                     | `/policy/members`                                                 | P1            | Preserve member table/tabs/pagination; live-verified 25-row pages and 1000-row clamping behavior. |
| map-cycle operations                              | `/settings/maplist`                                                | P1            | Live-verified create, activate, restore, and delete round trip. Parse map-list selector, active flag text, `mapcycle` textarea, and exact one-active invariant. |
| advertisement getters/setters                     | `/settings/general`                                                | P2            | Implement through `settings_ServerAdvertisementInterval` and `settings_ServerAdvertisementMessages`.                                                   |

The adapter uses BeautifulSoup parser selectors rather than a stable wire
schema. Fixtures are therefore acceptance inputs: mock responses must preserve
element IDs, named controls, table headings/order, and empty-list text rather
than merely return semantically equivalent HTML.

Tracking and members have live-verified 25-row pagination; banned-ID pages
render a full table without paging controls in settled 50-row and 1000-row
passes. Boundary fixtures cover 0, 1, 24, 25, 26, 50, and 1000 rows. A 6000-row
pass did not restore a healthy WebAdmin listener and remains unsupported.
Session-ban and toxic-player large-list boundaries remain
`prerequisite-unavailable`.
