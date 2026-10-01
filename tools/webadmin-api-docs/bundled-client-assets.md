# Bundled WebAdmin Client Assets

The RS2 server installation includes WebAdmin templates under `ServerAdmin/`
and browser assets under `images/`. A configured optional source-data root
contains those directories. They are a useful source of
**client-contract evidence**: exact form field names, AJAX payloads, expected
DOM identifiers, and browser-side state handling.

They are not the compatibility authority. The live development server remains
authoritative for exposed routes and actual server state transitions. In
particular, the bundle includes `multiadmin.html` and `policy_hashbans.html`,
but authenticated requests to `/multiadmin` and `/policy/hashbans` on the
target server return rendered 404 pages. A mock must not implement a bundled
template merely because it exists on disk.

## Useful verified client behavior

| Asset | Client contract added to the mock documentation |
| --- | --- |
| `current_rs2_players.html` and `current_rs2_players_row.inc` | Player commands are AJAX `POST`s to `pageUri + "/data"`. Although the enclosing form holds `playerid`, `playerkey`, player name, and submitter fields, JavaScript sends only `ajax=1`, `action`, and `playerkey`. A `<kicked playerkey="..."/>` response removes that row; a `<text playerkey="..." label="..."/>` response relabels the `toggletext` action. |
| `dialog_kick.js` | Moderation dialog fields are `__IdType`, `__UniqueId`, `__PlayerName`, `__Reason`, `__ExpNumber`, `__ExpUnit`, and optional `__NotifyPlayers=1`. Expiry number choices are blank or 1–12; allowed units are `Never`, `Hour`, `Day`, `Month`, and `Year`. Kick/session-ban dialogs hide expiry controls; ID-ban dialogs show them. |
| `current_chat.html` and `current_chat.js` | Send and poll are both AJAX `POST`s to `/current/chat/data` with `ajax=1`; a poll sends no message/team value. The browser starts after `chatRefresh`, polls recursively, and keeps only the most recent 50 `.chatmessage` DOM nodes. This is browser retention, not evidence that the server truncates its underlying chat state to 50. |
| `current_change.html` and `current_change.js` | Game-type change sends `ajax=1`, `gametype`, `mutatorGroupCount`, and checked `mutgroup*` values to `/current/change/data`. Client selection rules keep matching mutator values synchronized, make non-empty radio choices mutually exclusive within a group, and restore the first option when a multi-choice group would otherwise be empty. |
| `paging.js` and `paging.inc` | Page controls set the enclosing form's `action` to `firstpage`, `previouspage`, `nextpage`, or `lastpage` before submission. |
| `dynamictabs.js` | Dynamic settings/policy tabs persist the selected tab through `__CurrentTabIndex` and submit the enclosing form on tab selection. |

### Verified player-action route discrepancy

`current_rs2_players.html` intercepts the form and posts actions to
`/current/players/data`. On the investigated live build, that route is still
handled by the legacy `QHCurrent` handler. The RS2 dynamic menu handler that
implements role kick, team swap, tracking, membership, aliases/notes, and
whisper replaces `/current/players` instead. Consequently, an extended action
submitted through the bundled browser AJAX path is unrecognised by the legacy
handler and falls through to an ordinary kick. A controlled `whisper` probe
confirmed this outcome. The mock must preserve the browser-facing discrepancy;
the non-JavaScript `POST /current/players` fallback remains a separate pending
test.

## Mock implications

For `rs2wapy`, server behavior still matters more than visual effects. The mock
should emit stable hidden fields, result XML, messages, forms, and table shapes
that the client parses. It does not need to implement jQuery animations,
dialogs, table sorting, or client-side pruning. It should accept the browser's
actual POST envelopes, including harmless `ajax=1` flags, so tests using either
the library or browser-shaped requests remain representative.
