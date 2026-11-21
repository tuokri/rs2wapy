# RS2 WebAdmin Experimental Discovery Runbook

**Date:** 2026-09-26 (UTC)
**Last updated:** 2026-11-21 (UTC)

## Discovery checkpoint — server shutdown pause (updated 2026-11-21 UTC)

Discovery is paused after a synthetic pagination seed
attempt knocked WebAdmin offline during config reload. All WebAdmin sessions
used for the completed observations have been logged out. The three config
backups were restored immediately, and the temporary seed script was retained
for a later restart-safe rerun. A repeat session-ban probe submitted and revoked a session ban for `PLAYER_B`, and the server later left a
blank unnamed session-ban row that remained after both the normal revoke and
the probe's attempted blank-row cleanup. At the resumed baseline, `/policy/session`
was clean. The live `PLAYER_A` account remains a permanent Admin member; do not remove that membership without explicit
authorization. Do not repeat completed scenarios merely to reconstruct evidence.

### Completed evidence

- Baseline capture/sanitization harness, anonymous/remembered session handling,
  MultiAdmin SHA-1 login, enabled/disabled accounts, and a restricted-account
  authorization matrix are captured and validated.
- Empty-server reads, notes save/restore, map travel round trip, policy
  validation/add/update/delete cleanup, welcome-settings restore, and harmless
  console-command behavior are live-verified.
- With one controlled player: player table/action rendering, voice mute/unmute,
  session-ban followed by revoke, permanent ID-ban followed by revoke, and a
  post-reconnect read-only crawl are captured.
- The non-JavaScript `POST /current/players` route is now independently
  verified as a dynamic full-HTML action handler: `makemember` with a one-hour
  non-admin expiry created a member record and direct `cancelmembership`
  restored the player and members-page baseline. This is distinct from the
  browser AJAX route.
- A controlled tracking-record alias attach/delete round trip is captured.
  The pre-existing record had an empty alias baseline; `attachalias` rendered
  the marker and changed the row action to `deletealias`, which restored the
  exact baseline on a fresh GET.
- A controlled tracking-note round trip is captured. The pre-existing detail
  dialog reported zero notes; `attachnote` created one marker note, and
  `deletenote` with its generated note ID restored zero notes.
- A one-player direct-form `swapteam` request is captured. It returned normal
  HTML but did not change the rendered team, so no restore request was sent;
  retest this state transition with two controlled players.
- Two controlled players are now live-verified in independent WebAdmin session
  captures, including current, player, squad, chat-page, and chat-data
  baseline responses.
- A correctly held two-session chat capture established cursors before human
  sends. Both sessions received human all-chat markers `a1` and `b1` and
  team-chat markers `a2` and `b2` in the same captured order; both team
  markers included `(Team)` and team color, and each immediate second poll was
  empty.
- The player action menu is misleading on this build: its bundled JavaScript
  posts to `/current/players/data`, which remains on the legacy handler.
  `whisper` was submitted with a harmless marker but fell through to an
  ordinary kick. Source inspection explains this behavior. The mock contract
  now records the browser-wire behavior as authoritative.
- WebAdmin-originated chat is now live-verified with both controlled clients.
  The all-chat marker `wa` was visible to both. The team-0 marker `wt` was
  visible only to the controlled client on team 0.
- A two-player direct-form `POST /current/players` `swapteam` request is
  captured. It again returned normal HTML without changing the controlled
  player's rendered team; no cleanup action was necessary.
- A direct-form `POST /current/players` `whisper` with `__Input=ww` is
  captured. The controlled recipient confirmed visibility and remained
  connected. This safe path is distinct from the browser AJAX route, whose
  unrecognised `whisper` action falls through to a kick.
- A two-player browser-shaped kick is captured. It removed the authorized
  target from the player table while the controlled observer remained present.
  After manual reconnect, two independent read-only sessions confirmed both
  controlled players again.
- A two-player browser-shaped session ban is captured. It removed the
  authorized target, created a session-ban record, and left the controlled
  observer present. The probe revoked the record immediately; after manual
  reconnect, two independent read-only sessions again confirmed both players.
- A 2026-11-20 session-ban repeat reproduced a blank unnamed residue in
  `/policy/session` after standard revoke. The enhanced cleanup probe attempted
  to revoke that residue and the row still remained. SDK inspection explains
  that the row is a `ZeroNetID` dummy retained by
  `ROAccessControl.SafeRemoveSessionBannedId`; the session-ban array is iterated
  by `ROPolicySessionBans`, and `ROTracking.RevokeSessionBan` ignores the dummy.
  It is not an active ban for a real player, but exact mock compatibility requires
  modeling or explicitly simplifying this post-revoke row.
- The 2026-11-20 post-pause baseline captured both controlled players in two
  independent sessions and showed an empty `/policy/session` table with no named
  or dummy rows.
- A post-pause temporary permanent-ID-ban lifecycle verified `<kicked>`, active
  banned-ID creation, immediate revoke, empty fresh ban state, observer retention,
  and successful manual reconnect of the target.
- A 2026-11-20 post-team-join baseline verified North/South team assignment for
  both controlled players and showed no squads while the round timer was active.
- A 2026-11-20 read-only 34-route crawl refreshed settings, campaign, map-cycle,
  workshop, policy, and current-game captures. It found 37 HTTP 200 responses
  and the existing rendered `/policy/hashbans` 404.
- A 2026-11-20 welcome-screen round trip saved a marker MOTD, verified it by a
  fresh GET, restored the exact baseline form, and confirmed `TBVal=1` under an
  enabled welcome-screen checkbox.
- A 2026-11-20 map-cycle round trip created cycle #2, activated it, restored
  cycle #1 as active with the exact baseline text, deleted cycle #2, and proved
  a fresh final GET contained only the original active cycle.
- A 2026-11-20 general-settings round trip changed advertisement interval
  30→31, verified the live page, restored 30, and verified exact readback.
- A 2026-11-20 gameplay-settings round trip changed
  `FriendlyFireArtilleryPunishScale` 0.1000→0.2000, verified the live page,
  restored 0.1000, and verified exact readback. The probe includes a
  60-second remaining-match safety guard.
- A 2026-11-20 gametype-settings round trip changed Territories
  `settings_RoundLimit` 1→2, verified the live page, restored 1, and verified
  exact readback.
- A 2026-11-20 system-settings round trip changed `settings_ChatRefresh`
  5000→5010, verified the live page, restored 5000, and verified exact readback.
- A 2026-11-20 server-actors round trip appended a disposable test actor,
  read it back, restored `IpDrv.WebServer`, and proved exact final readback.
- A 2026-11-21 mutator refresh found no selectable mutators and no mutators
  available for the live game type. Mutator save/edit remains
  `prerequisite-unavailable` until a reversible disposable mutator is installed.
- A 2026-11-21 campaign-settings round trip changed
  `CampaignRegionVoteTime` 45→50, verified the live page, restored 45, and
  verified exact readback. Campaign region-map edit/delete/activate/reset remains
  gated behind a disposable campaign snapshot.
- A 2026-11-21 policy-validation round trip verified malformed and missing
  policy errors, duplicate `ALLOW` acceptance, `DENY` update, delete cleanup,
  and exact baseline restoration.
- A 2026-11-21 read-only pagination control pass captured baseline,
  first/previous/next/last controls for tracking, members, banned IDs, and
  session bans. It established small-state behavior only, not large-list limits.
- A 2026-11-21 synthetic pagination seed attempt wrote tracking/member/bans
  test rows to `ROTrackDb.ini`, `ROMemberDb.ini`, and `ROGame.ini`, then a
  map-change/config reload knocked WebAdmin offline. The three pre-seed config
  backups were restored immediately; the temporary seed script remains in the
  workspace for a future server-restart-safe rerun.
- A 2026-11-20 post-team-join baseline and post-map-cycle baseline captured
  North/South roster state, team join stability, the Hill 937 map, and clean
  banned-ID/session-ban tables.
- A 2026-11-20 Commander role-kick captured an occupied North `COMMANDER`
  before action and a direct-form full-HTML response saying the player would be
  kicked on next death. The immediate readback showed `RIFLEMAN`, an
  North `ALPHA` squad appeared, and both controlled players remained connected.
- A 2026-11-20 direct-form team-swap request returned "has swapped team" but
  the immediate full player-table read retained the target on the original team,
  so no restore request was sent.
- A 2026-11-20 direct-form whisper sent marker `ww` to `PLAYER_B`; the server
  returned success, the recipient confirmed receipt, and both controlled players
  remained connected.
- A two-player browser-shaped permanent ID-ban returned the expected
  `<kicked>` XML result and removal message, while the immediately fetched
  full player table still showed the target. The observer remained present;
  the temporary ID-ban cleanup completed before the human reconnection
  checkpoint, and two independent read-only sessions then confirmed both
  players. Treat the immediate full-table response as potentially stale; the
  browser removes its row from the action XML, while the separate one-player
  lifecycle fixture proves ID-ban record creation and revocation.
- A two-player direct-form `kickfromrole` is captured for an occupied commander
  role. Its full-HTML response says the player will be kicked from the role on
  their next death, but the controlled player immediately reported return to
  role selection as a grunt, without a server disconnect. SDK inspection shows
  immediate enforcement except for a flying helicopter pilot, whose removal is
  deferred until a safe landing/bail-out. A post-transition two-session
  read-only crawl confirmed both players remained present.
- A browser-shaped legacy `kick` request with a syntactically plausible but
  nonexistent player key returned `<nop/>` rather than `<kicked>`; both
  controlled players remained present. This is the safe stale-key branch for
  mock error handling.
- A current player was made a member from the Players form, updated through
  the Members form with Admin enabled, and manually reconnected. The live
  player table then rendered that player as Admin. A browser-shaped
  `sessionban` against that logged administrator returned `<nop/>`, left the
  administrator and observer connected, and created no session-ban row. A
  same-name historical Members entry with a different game account ID did not
  confer admin status to the live connection; model membership by account ID.
  A timed map transition invalidated the subsequent sanitized reproduction
  capture, so retain this result as observed evidence and rerun its dedicated
  capture only after the server is stable.
- A current player was made a member from the Players form, updated through
  the Members form with Admin enabled, and manually reconnected. The live
  player table then rendered that player as Admin. A browser-shaped
  `sessionban` against that logged administrator returned `<nop/>`, left the
  administrator and observer connected, and created no session-ban row. A
  same-name historical Members entry with a different game account ID did not
  confer admin status to the live connection; model membership by account ID.
- With a captured same-team, same-squad baseline and autobalance disabled, one
  controlled team kill produced one additional victim death. The apparent
  killer row's score fell by 10 while its rendered kill count did not increase.
  This is an observed result for this server/profile, not a universal scoring
  rule; fixture sanitization and sorting mean per-player identity must be
  preserved by a future delta probe rather than inferred from row position.
- After the controlled players killed each other once, two independent
  read-only sessions captured the rendered current-game/player/squad/chat
  state. The before and after player rows place them on opposite teams, with
  one additional kill and death each. Other score and role state also changed
  over the capture interval, so this fixture must not attribute a score delta
  to either kill or represent team-kill behavior.
- A read-only Toxic Players page capture after those reciprocal enemy kills
  remained empty. This does not test the team-kill threshold; do not escalate
  toward an unknown threshold without separate authorization.
- A human-authorized direct-form `resetsquadname` reset a rendered custom
  squad name. The endpoint exposed no rename/restore operation, so the human
  restored the original name manually; a two-session read confirmed that
  restoration. Model reset as an irreversible server-side mutation from the
  WebAdmin API perspective.
- The bundled squad page's browser AJAX target, `/current/squads/data`, is not
  registered on this server. An authenticated actionless POST returned the
  normal full-HTML 404 page; the direct `/current/squads` form is authoritative.

### Resume with

1. **SERVER-SHUTDOWN PAUSE / NEXT RESUME — 2026-11-21 (UTC).** Before restarting,
   verify `ROTrackDb.ini`, `ROMemberDb.ini`, and `ROGame.ini` match the backed-up
   snapshots. Start the dedicated server and WebAdmin, wait for the
   match timer/current game to stabilize, then capture `/current`,
   `/current/players`, `/current/squads`, `/policy/bans`, and `/policy/session`.
   The retained seed script `tools/seed_synthetic_pagination.ps1` is operator-only;
   restore its three backups before server restart and rerun only after a clean
   synthetic seed/level reload plan is approved.
2. Recheck the previously observed `ZeroNetID` session-ban dummy. It is now
   source-explained and was absent in a later post-pause baseline; preserve
   whether it renders after the restart and server state is reloaded.
3. Proceed with non-destructive discovery first: read-only tracking/members/
   paging routes, mutator availability, campaign settings/region maps, and
   remaining settings subpages.
4. Before mutator-specific map-change tests, install or seed an approved
   reversible mutator. Capture no-mutator, single-mutator, multiple-mutator,
   radio/shared mutator, `urlextra` accepted/rejected, travel, and exact restore
   behavior.
5. Defer password changes until a disposable account/recovery path is supplied.
   Defer campaign region-map reset/delete/activate and destructive Workshop
   operations until exact snapshots and explicit approval exist.
6. Do **not** use the browser-shaped `/current/players/data` route for
   `kickfromrole`, team swap, tracking, membership, alias/note, or whisper:
   on this build it kicks the target. Its completed failed fixture is retained
   as evidence but is deliberately excluded from the validated fixture set.
7. The controlled player currently renders as tracked and has an existing
   tracking-table entry, but exposes neither `enabletracking` nor
   `disabletracking`; do not alter that pre-existing record. Record this as a
   tracking precondition unavailable rather than manufacturing a new baseline.
8. Defer role paths until their role preconditions exist. Every disruptive test
   still requires a fresh human reconnect checkpoint. Before a future
   two-player ID-ban repeat, capture the bans page after the action and model
   the immediate full-table target row as stale rather than as an action
   failure.

The current validated checkpoint fixture sets include `phase4-player-readonly`,
`phase4-player-actions`, `phase4-banid-roundtrip`,
`phase4-post-banid-reconnect`, `phase4-player-form-membership`,
`phase4-tracking-alias-roundtrip`, `phase4-tracking-note-roundtrip`, and
`phase4-player-form-swapteam`, `phase5-two-player-readonly`,
`phase5-admin-target-prebaseline`, `phase5-admin-sessionban-denied`,
`phase5-chat-human-markers-held-20261120`,
`phase5-two-player-readonly-20261120`,
`phase5-stale-player-key-20261120`,
`phase5-squad-data-route-20261120`,
`phase5-toxic-players-after-teamkills-20261120`,
`phase5-two-player-kick-20261120`,
`phase5-post-kick-reconnect-20261120`,
`phase5-webadmin-chat-send`, `phase5-player-form-swapteam`, and
`phase5-player-form-whisper`, `phase5-two-player-kick`, and
`phase5-post-kick-reconnect`, `phase5-two-player-session-ban`, and
`phase5-post-session-ban-reconnect`, `phase5-two-player-permanent-ban`, and
`phase5-post-permanent-ban-reconnect`, `phase5-two-player-role-kick`,
`phase5-two-player-role-kick-commander`, and `phase5-post-role-kick`. The raw
server log remains operator-only and is not a repository fixture. The
validated stale-key and gameplay-state sets are `phase5-stale-player-key` and
`phase5-post-reciprocal-kills`; the negative toxic-player set is
`phase5-toxic-players-after-teamkills`; squad reset/restoration is recorded in
`phase5-squad-reset` and `phase5-post-squad-reset-restore`; the squad AJAX
404 is recorded in `phase5-squad-data-route`. The controlled team-kill
baseline/delta sets are `phase5-team-kill-baseline` and
`phase5-one-team-kill-after`.

## Purpose and completion target

This runbook is a top-to-bottom procedure for a human–LLM pair to collect the
remaining real-server evidence needed for approximately 95% confidence in an
in-memory Sanic WebAdmin mock. The mock need not recreate UE3; it needs to
reproduce the observable HTTP, HTML, XML, session, and in-memory state
semantics that `rs2wapy` and browser-shaped clients rely on.

The existing documentation and fixtures are the baseline. Do not repeat an
already live-verified sequence unless server configuration or WebAdmin build
changes. Every new result must be marked `live-verified`,
`live-verified-denied`, `not-exposed`, or `prerequisite-unavailable` in the
contract.

This is an estimated **90–125 stateful scenarios**, not 90–125 individual
requests. A scenario normally means baseline read, operation, readback,
cleanup, and final readback. The dedicated synthetic large-list/pagination
phase is estimated to require 8–12 of those scenarios.

## Roles, notation, and non-negotiable safety rules

| Name            | Meaning                                                                    |
|-----------------|----------------------------------------------------------------------------|
| `ADMIN_FULL`    | Authorized full WebAdmin administrator used by the probe.                  |
| `ADMIN_LIMITED` | A disposable MultiAdmin account with intentionally restricted permissions. |
| `PLAYER_A`      | Controlled non-admin human player.                                         |
| `PLAYER_B`      | Second controlled human player.                                            |
| `BOT_N`         | Controlled bot used for table/squad/paging variations.                     |
| `RUN_MARKER`    | Unique, non-sensitive identifier such as `mock-doc-YYYYMMDD-N`.            |
| Snapshot        | Sanitized before-state capture plus a precise restoration procedure.       |

1. Never store credentials, cookies, form tokens, raw player IDs, IP addresses,
   or raw captures in the repository.
2. Before every mutation, capture the affected page and prove that the
   disposable record does not already exist.
3. Before drawing any conclusion from a player-affecting action, capture the
   rendered player and current-game scoreboards plus squads, and explicitly
   record each controlled player's team and squad. This is a live server:
   autobalance, map travel, role changes, score events, and player actions can
   change the state between steps. Do not infer team-kill, score, squad, or
   player-action semantics from a state whose preconditions were not captured.
4. Use `RUN_MARKER` in every disposable policy entry, note, alias, map list,
   campaign object, or workshop test object.
5. Immediately restore bans, session bans, policies, membership/tracking data,
   map selection, settings, and configuration changes. Verify restoration with
   a fresh GET, not merely the POST response.
6. If cleanup fails or its outcome is unknown, stop all further mutations,
   inspect the live state, restore it manually, and record the incident. Do
   not continue on the assumption that cleanup succeeded.
7. Do not test arbitrary console commands, real Workshop downloads, shared-IP
   bans, production credentials, or destructive campaign reset unless the
   human explicitly authorizes that exact operation and has a restore plan.
8. Keep the baseline plaintext-auth and MultiAdmin/SHA-1-auth test passes
   separate. Record the active authentication mode in every fixture index.
9. Treat a timed map change as an external interruption. Refresh `/current`
   before a multi-request mutation, do not start one near the end of a round,
   and re-authenticate/re-establish state if travel occurs during a sequence.
   To diagnose a suspected transition, capture `/current` and record the
   current map/game type plus the rendered scoreboard before interpreting a
   missing player, changed team/squad, or unexpected action response as an
   endpoint result.

## Standard sequence template

Use this template for every numbered scenario below.

1. **Agent:** identify the exact endpoint, form, expected source/template
   behavior, sanitization rules, and cleanup operation before making a write.
2. **Agent:** capture a sanitized baseline GET and assert any precondition.
   For player/gameplay scenarios, snapshot player rows, current-game
   scoreboard, and squads, including controlled-player team/squad membership.
   If a timed map change is suspected, make this `/current` snapshot the first
   diagnostic artifact and compare its map/game/scoreboard state with the
   pre-transition snapshot before continuing.
3. **Human required:** complete the indicated player/server/configuration
   checkpoint.
4. **Agent:** submit one narrowly scoped request and capture the response.
5. **Agent:** fetch the affected state and compare it with the expected
   transition.
6. **Agent:** restore state in `finally`-style cleanup, even if the preceding
   readback failed.
7. **Agent:** fetch fresh state, verify restoration, sanitize captures, update
   `contract.yaml` and the API reference, and run `tools/verify_docs.py`.

## Phase 0 — Baseline and test harness

### 0.1 Record the run baseline

- **Agent:** record WebAdmin build banner, configured base path, active auth
  mode, current map/game type, player count, policy counts, active bans,
  session bans, and relevant settings/map-list/campaign identifiers.
- **Agent:** create a sanitized fixture-set directory named for the run class,
  never for a real player/server.

> **HUMAN REQUIRED — confirm safe test window**
>
> Confirm the server is a development instance, other users will not be
> affected, and provide the current restoration baseline if a test changes
> map, campaign, settings, or server configuration.

### 0.2 Validate the capture harness before mutation

- **Agent:** run an authenticated read-only crawl and `tools/verify_docs.py`.
- **Agent:** prove that sanitization removes visible player-table names, player
  keys, unique IDs, IPs, cookies, tokens, passwords, and hash values.
- **Agent:** run an intentional fixture-verifier failure only against a local
  temporary copy, never committed evidence.

## Phase 1 — No players and no meaningful side effects

Target: **20–30 scenarios**. Complete this phase with an empty human player
list; bots are also absent unless a scenario says otherwise.

### 1.1 Authentication and HTTP-state matrix

| Scenario | Agent sequence                                                                              | Expected evidence                                                       |
|----------|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| A1       | GET each protected route without a session                                                  | Login page with HTTP 200 versus 401/403/redirect behavior.              |
| A2       | Login with omitted token, omitted username, omitted password, and malformed `password_hash` | Validation/error shape without deliberately supplying a wrong password. |
| A3       | Login with `remember` values exposed by the page; restart a cookie jar; logout              | `authcred`/session cookie scope, max-age, reuse, and invalidation.      |
| A4       | Two independent authenticated cookie jars; logout one                                       | Session isolation and unaffected second session.                        |
| A5       | GET/POST route/method matrix for active endpoints, trailing slash, unknown child route      | Rendered 404/405/login behavior and headers.                            |

> **HUMAN REQUIRED — do not change credentials during this phase**
>
> Authentication experiments depend on known working credentials. Do not rotate
> the account password or restart the server until the cookie/session captures
> are complete.

### 1.2 Data, selectors, and empty states

- **Agent:** probe `/data` for each source-visible supported `type`, missing
  type, and unknown type.
- **Agent:** capture `/current`, `/current/players`, `/current/squads`, chat,
  policy, tracking, members, bans, session-bans, toxic players, workshop, and
  all settings pages in their empty-state forms.
- **Agent:** exercise read-only selections for every game type, mutator,
  map-list index, campaign tab, settings tab, sort field, and reverse value.
- **Agent:** call `/current/change/data` for each game type and no-mutator
  case. Record whether `ajax=1` is optional or required.
- **Agent:** fetch representative `/images/...` JS/CSS assets with and without
  gzip query suffixes if browser fidelity is in scope.

### 1.3 Confirm bundle-versus-live discrepancies

- **Agent:** recheck `/multiadmin` and `/policy/hashbans` before MultiAdmin is
  enabled; preserve the current rendered-404 evidence.
- **Agent:** compare the live `login.html`, player, chat, change-map, paging,
  and dynamic-tab HTML/JS behavior with bundled assets. Record only observed
  differences.

## Phase 2 — Players/bots present; read-only observation

Target: **12–18 scenarios**. No player action is submitted in this phase.

> **HUMAN REQUIRED — seed players now**
>
> `PLAYER_A` must join as a non-admin. If possible, add `PLAYER_B` and 2–5
> bots. Leave them connected and avoid changing teams/roles until told.

### 2.1 Player, game, and squad render matrix

- **Agent:** capture `/current` and `/current/players` for one player, mixed
  players/bots, spectator state, each team, and empty/unassigned role.
- **Agent:** capture action-menu differences for admin, non-admin, member,
  tracked, spectator, and bot rows without invoking an action.
- **Agent:** exercise `sortby`/`reverse` permutations and enough rows for
  paging if the target exposes it.
- **Agent:** capture `/current/squads` with no squad, one squad, several
  squads, and both-team layouts.
- **Agent:** capture current-game team/rule/scoreboard changes caused by
  player/bot presence only.

### 2.2 Read-only policy and chat matrix

- **Agent:** read chat history from two independent WebAdmin sessions and
  compare cursor behavior without posting.
- **Agent:** read tracking/member/ban/session-ban pages after controlled data
  has been seeded by an earlier restored sequence; test first/previous/next/
  last paging and `__CurrentTabIndex`.

> **HUMAN REQUIRED — do not send chat messages yet**
>
> This phase establishes baseline rendering. The human should not create new
> chat, member, tracking, or ban state until Phase 5.

## Phase 3 — No players; controlled state-changing sequences

Target: **25–35 scenarios**. Some of these alter server configuration rather
than merely an in-memory session; use a human-approved snapshot and restore.

### 3.1 Current-game, travel, and console

| Scenario | Endpoint/flow                                                      | Restore condition                                     |
|----------|--------------------------------------------------------------------|-------------------------------------------------------|
| C1       | `/current` notes save → GET readback                               | Restore original notes.                               |
| C2       | `/current/change action=update`                                    | Compare option/mutator fragment; no lasting change.   |
| C3       | `/current/change action=change` → repeated `/current/change/check` | Return to baseline map/game type and wait for `ok`.   |
| C4       | `/current action=resetCampaign`                                    | Only with a disposable campaign baseline; restore it. |
| C5       | `/console` harmless help/version/status and unknown command        | No game/admin command; capture output/error form.     |

**Deferred map-change matrix:** separately capture `/current/change`,
`/current/change/data`, and `/current/change/check` after mutators are installed:

- change with one mutator, multiple mutators, radio-group choices, shared
  mutator values, and no mutator;
- change with approved URL variables in `urlextra`, including password/port
  rejection boundaries and one reversible recognized option;
- compare `action=update` fragments, `action=change` travel URLs, `503` polling,
  session expiry, and exact baseline restoration;
- preserve the exact parameter names and state before a final map selection.

> **HUMAN REQUIRED — approve travel/reset window**
>
> Confirm that no players are connected, identify the baseline map/game type,
> and confirm the exact command or procedure that restores it after travel.

### 3.2 Policy and direct-ban mutation coverage

- **Agent:** policy update of a `RUN_MARKER` TEST-NET entry, then readback and
  deletion.
- **Agent:** duplicate policy, malformed mask, invalid policy value, and
  missing-field validation paths.
- **Agent:** `/policy/bans action=add` using a disposable synthetic unique ID,
  each supported ID type, finite expiry and `Never`, then revoke and fresh GET.
- **Agent:** multiple-ID revoke, invalid ID, duplicate ban, and edit/update
  flows only on disposable entries.
- **Agent:** session-ban revoke edge cases: empty selection, unknown ID,
  comma-separated IDs, duplicate revoke.

### 3.3 Settings, map list, campaign, and workshop

For each route family below, test one valid save, one validation boundary, one
readback, and restoration. Preserve submitted field names and result messages.

- `/settings/general`, `/settings/general/gameplay`, and welcome settings;
  include `liveAdjust` present/absent behavior.
- `/settings/gametypes` select/save and `/settings/mutators` select/save.
- `/settings/system` including `/system/allowancecache action=rebuild` if
  available.
- `/settings/serveractors action=save` with a reversible disposable value.
- `/settings/maplist`: save/edit, activate, delete, empty/malformed map cycle,
  then restore exactly one original active cycle.
- `/settings/campaign`: tab selection, save, activate, delete, reset only for
  disposable campaign data.
- `/current/workshoptool`: invalid/missing input and non-downloading UI flows
  first. Download/add/update/delete requires separate explicit approval and a
  disposable Workshop item.
- `/settings/general/passwords`: defer until all other work is complete. Use a
  disposable account or a human-operated recovery path; do not capture values.

> **HUMAN REQUIRED — configuration snapshot and restore authority**
>
> Before any settings, map-list, campaign, server-actor, password, or Workshop
> mutation, provide/confirm the baseline values and authorize restoration. If
> a change survives WebAdmin restart, treat it as persistent and verify its
> manual restoration too.

## Phase 4 — One player; controlled side effects

Target: **20–30 scenarios**. `PLAYER_A` must be a non-admin and explicitly
authorize temporary disruption. Prefer a fresh player connection before every
kick/ban action.

> **HUMAN REQUIRED — PLAYER_A must join manually now**
>
> Confirm `PLAYER_A` is the intended test player, is not a logged-in admin or
> developer, and is prepared to reconnect after kick/session-ban/ID-ban tests.

### 4.1 Player action matrix

**Observed compatibility correction (complete):** the listed extended actions
appear in the rendered action menu, but browser JavaScript submits them to
`/current/players/data`. That endpoint's legacy handler handles voice mute,
voice unmute, kick, session ban, and ID ban; an unrecognised action falls
through to kick. The `whisper` test established this live. Model this behavior
for browser-shaped requests. The following extended-action rows now refer to
the separate non-JavaScript form fallback, `POST /current/players`, which is
still pending live verification.

| Scenario | Action                                                          | Required verification and cleanup                                                                                       |
|----------|-----------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| P1       | `kickfromrole`                                                  | Capture action XML and role/squad/current-page change; let player choose/recover role.                                  |
| P2       | `swapteam`                                                      | Verify player row, team totals, and squad consequences; restore original team.                                          |
| P3       | `whisper`                                                       | Capture success/error XML; use a non-sensitive `RUN_MARKER` payload.                                                    |
| P4       | `attachalias`, `attachnote`                                     | Read tracking detail; delete alias/note and verify removal.                                                             |
| P5       | `enabletracking`, `disabletracking`                             | Read policy tracking state after each transition; leave disabled unless baseline says otherwise.                        |
| P6       | `makemember`, `cancelmembership`                                | Read members page; remove membership and verify.                                                                        |
| P7       | stale `playerkey`, unknown action, empty reason, invalid expiry | For `/data`, capture the legacy no-player/error or kick fallback exactly; no unknown action should be assumed harmless. |
| P8       | admin/dev target denial branches                                | Use a controlled admin/dev player; verify no state change.                                                              |
| P9       | finite ID-ban expiry                                            | Prefer one-hour/one-day disposable ban, revoke immediately, and verify rejoin.                                          |

### 4.2 One-player policy and squad flows

- **Agent:** exercise policy tracking details, delete-entry, alias/note edit and
  delete paths on records created in P4/P5, then clean them up.
- **Agent:** exercise member edit/add/update/alias actions on the controlled
  player, then restore no-membership baseline.
- **Agent:** create/rename/reset a controlled squad through `/current/squads`
  and restore baseline.
- **Agent:** test toxic-player removal only if a controlled toxic entry can be
  created and removed without affecting unrelated data.

### 4.3 IP-ban decision gate

The SDK’s live action dispatch appears to have `banip` disabled, but that must
not be assumed for every server configuration.

> **HUMAN REQUIRED — explicit IP-ban approval**
>
> Before probing `banip`, confirm that `PLAYER_A` uses a unique disposable IP,
> no other person/service shares it, and the human has identified the exact
> policy entry/removal procedure. Do not test shared/NAT/public addresses.

- **Agent:** capture baseline policy and player state, submit one `banip`,
  immediately locate/remove any created policy/ban record, then confirm that
  `PLAYER_A` can reconnect. If the action is a no-op, capture that response and
  stop; do not manufacture a policy deny rule against a real player IP.

## Phase 5 — Two or more players; controlled side effects

Target: **10–15 scenarios**. This phase validates interaction semantics that a
single-player test cannot establish.

> **HUMAN REQUIRED — two controlled players must join manually now**
>
> `PLAYER_A` and `PLAYER_B` must join on known teams. Confirm both can
> reconnect, accept temporary messages/team changes, and are not unrelated
> public users. Add bots only if needed for tables/paging.

### 5.1 Chat, whisper, and cursor flows

1. **Human required:** `PLAYER_A` sends one all-team marker and one team marker;
   `PLAYER_B` sends one all-team marker and one team marker.
2. **Agent:** poll from two independent WebAdmin sessions before and after each
   marker; document visibility, ordering, duplicate behavior, and cursor
   advancement.
3. **Agent:** send WebAdmin all-team and team messages; compare player-visible
   outcomes where the humans can report them.
4. **Agent:** issue whisper `PLAYER_A → PLAYER_B`, then an offline/invalid
   target whisper; capture XML/messages and any visible recipient behavior.

> **HUMAN REQUIRED — players must send the requested chat markers now**
>
> Do not include private information. Use the displayed `RUN_MARKER` exactly so
> the agent can correlate the resulting chat fragments.

### 5.2 Team, squad, moderation, and scoreboard flows

- **Agent:** swap `PLAYER_A` to `PLAYER_B`’s team and back; compare both player
  rows, team totals, rules/scoreboard, and squad listing.
- **Agent:** mute/unmute one player while the other can report observable voice
  behavior, if practical; WebAdmin messages alone remain the minimum evidence.
- **Agent:** kick `PLAYER_A` while `PLAYER_B` remains connected; capture table
  refresh/current-game totals, wait for `PLAYER_A` reconnect, and verify
  `PLAYER_B` was unaffected.
- **Agent:** session-ban or ID-ban `PLAYER_A`, revoke immediately, then verify
  rejoin and that `PLAYER_B` remains connected and unmodified.
- **Agent:** create a shared squad/role state, run `kickfromrole` for one
  player, and observe effects on the other player/squad representation.
- **Agent:** if practical, use enough controlled bots/players to test all
  paging actions while preserving player-key identity across page changes.

> **HUMAN REQUIRED — waiting for a player to rejoin manually after kick/ban**
>
> After every disruptive moderation action, wait for the probe to confirm the
> corresponding ban/session-ban cleanup. The affected player must then rejoin
> manually before the next action begins.

## Phase 6 — MultiAdmin and SHA-1 compatibility profile

This is a separate server configuration profile. It must not overwrite the
baseline plaintext-auth evidence.

### 6.1 Configure and verify the profile

> **HUMAN REQUIRED — configure MultiAdmin and restart the server now**
>
> Enable MultiAdmin, create a disposable full administrator and a disposable
> restricted administrator, record the intended permission matrix outside the
> repository, and restart the development server. Confirm the baseline server
> configuration can be restored afterward.

1. **Agent:** GET login page and verify `hashAlg == "sha1"` in rendered script.
2. **Agent:** verify the browser formula from the bundled client:
   `password_hash = "$sha1$" + SHA1(password + username)`; submit empty
   `password` with the hash field populated.
3. **Agent:** capture successful login, failed/malformed-hash validation without
   repeated bad-password attempts, session cookie, `remember` cookie, logout,
   and login-page behavior after logout.
4. **Agent:** verify that plaintext-password submission is accepted, rejected,
   or transformed as actually observed. Do not infer this solely from source.
5. **Agent:** add a separately sanitized fixture index labeled
   `multiadmin-sha1`; never combine it with plaintext-auth captures.

### 6.2 MultiAdmin endpoint and authorization matrix

> **HUMAN REQUIRED — confirm disposable permission accounts**
>
> The restricted account must have enough access to log in but lack a known,
> non-destructive route permission. Do not remove the only recovery account.

- **Agent:** recheck `/multiadmin`; record whether it changes from baseline
  rendered 404 to an exposed page when MultiAdmin is enabled.
- **Agent:** capture page structure, list/select/edit flows, and validation
  responses using only disposable accounts.
- **Agent:** for `ADMIN_FULL` and `ADMIN_LIMITED`, test representative reads,
  denied reads, safe writes, and denied writes across current, players, policy,
  settings, console, and MultiAdmin pages.
- **Agent:** establish the exact denied behavior: hidden menu item, rendered
  page without controls, 403, login redirect, XML error, or no-op message.
- **Agent:** test permission change → fresh session/relogin → changed access →
  restore the original disposable permission set.
- **Agent:** test whether active sessions retain permission changes or require
  relogin.

### 6.3 Restore baseline profile

> **HUMAN REQUIRED — restore plaintext baseline or preserve profile intentionally**
>
> Decide whether the development server should return to its original
> non-MultiAdmin configuration. Restore it if required, restart the server, and
> confirm baseline plaintext login behavior and baseline 404 behavior again.

## Phase 7 — Synthetic large-list and database pagination discovery

Target: **8–12 stateful scenarios**. This phase is deferred until the server
can be isolated on a disposable database/configuration snapshot and populated
with synthetic records. It is required for complete pagination and large-list
documentation, but is separate from normal player/moderation testing.

> **HUMAN REQUIRED — provide a disposable pagination test profile**
>
> Create a restorable snapshot of the server databases/configuration used by
> tracking, members, ID bans, session bans, and toxic-player state. Supply a
> supported fake-data generator or operator procedure that creates synthetic
> records without using real players, public IP addresses, real Steam/Epic
> identities, or real ban policy entries. A normal server database backup and
> exact restore procedure are mandatory before seeding.

### 7.1 Seed and boundary matrix

- **Agent:** record the current/empty state and exact row/page count controls
  for every target route before seeding.
- **Agent:** generate and capture boundary sets for at least:
  0 records, 1 record, one record below the observed page size, exactly the
  observed page size, one record above it, two pages, and a deliberately
  large/overflow set approved by the human.
- **Agent:** test `firstpage`, `previouspage`, `nextpage`, `lastpage`,
  `__FirstVisibleRowIndex`, `__CurrentTabIndex`, sort fields, and reverse
  sorting around each boundary. Record clamping, index drift, empty-final-page
  behavior, stale row identity, and duplicate/unknown record keys.
- **Agent:** preserve synthetic aliases and relation-preserving placeholders in
  fixtures; never commit generated names, IDs, IP addresses, or database dumps.
- **Agent:** remove synthetic records in `finally` cleanup and restore the exact
  database/configuration snapshot. Verify restoration with fresh reads and,
  if the profile persisted across restart, a server restart.

### 7.2 Target route families

Test the route families below independently so failure in one database does not
invalidate the others:

| Route family | Synthetic-data scenario | Required evidence |
| --- | --- | --- |
| `/current/players` | Generate enough controlled bots or fixture-backed rows to exceed the live page size without affecting public players. | First/last page, sorting and reverse sorting, player-key stability across pages, spectator/bot rendering, final-page/empty-state behavior. |
| `/policy/tracking` | Generate synthetic tracking records with aliases, notes, and active/revoked punk entries. | Page size, tabs, `__FirstVisibleRowIndex`, detail-dialog IDs, note/alias identity across pages, and stale/delete behavior. |
| `/policy/bans` | Generate synthetic unique-ID bans with every supported ID type and finite/Never expiry variants. | Page size, duplicate/unknown IDs, revoke/edit selection, sorting/paging, and identity preservation after revoke. |
| `/policy/session` | Generate synthetic session-ban records or the same supported fixture mechanism, where explicit human authorization permits it. | Page-size behavior, multiple revoke selection, comma-separated IDs, unknown/expired records, and the `ZeroNetID` dummy-row transition. |
| `/policy/members` | Generate synthetic member records with tabs, expiry variants, and Admin/non-Admin flags. | Tab persistence, first/previous/next/last paging, update/delete behavior, duplicate IDs, and stale display-name/name-ID distinctions. |
| `/policy/toxicplayers` | Generate synthetic toxic entries only if a controlled, reversible mechanism exists. | Page size, sorting/paging, add/remove identity, and whether creation is source-only or live-supported. |

If no supported fake-data seeding mechanism exists for a route, record
`prerequisite-unavailable` rather than modifying a real database directly or
inferring behavior from source. Do not use this phase to probe real bans,
real account identities, shared IPs, or unrelated users.

## Phase 8 — Evidence integration and exit criteria

After each completed phase:

1. **Agent:** retain only sanitized response/request fixtures and index files.
2. **Agent:** update `api-reference.md`, `contract.yaml`,
   `rs2wapy-coverage.md`, and `bundled-client-assets.md` where applicable.
3. **Agent:** distinguish observed behavior from source-only/template-only
   behavior; do not turn a bundled page into a supported endpoint without a
   live response.
4. **Agent:** run syntax checks, YAML parse, and `tools/verify_docs.py`.
5. **Human required:** review the restoration checklist before starting the
   next phase.

The 95% mock-confidence threshold is met when all P0/P1 `rs2wapy` operations
have at least one success fixture, one empty/error/denied fixture where
applicable, explicit in-memory state transitions, and tested cleanup paths;
all active endpoint families have baseline/selection/error coverage; and the
plaintext and MultiAdmin/SHA-1 profiles are documented as separate auth modes.

Remaining untested high-risk functions may still be modeled in Sanic, but must
be explicitly labeled as source-derived or intentionally simplified rather
than live-compatible.
