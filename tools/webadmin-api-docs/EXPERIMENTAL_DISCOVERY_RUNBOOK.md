# RS2 WebAdmin Experimental Discovery Runbook

**Date:** 2026-09-26 (UTC)
**Last updated:** 2026-09-30 (UTC)

## Discovery checkpoint — pause here (updated 2026-09-30 UTC)

The current live-discovery block is paused at a clean two-player boundary. All
WebAdmin sessions used for the cursor observations have been logged out; no
membership, alias, note, ban, policy, map, or configuration mutation is
pending. The next prepared probe sends WebAdmin-originated chat markers and
has **not** been executed yet. Do not repeat completed scenarios merely to
reconstruct their evidence.

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
- Held two-session chat cursors received the human all-chat markers in the
  same newest-first order; neither received human team-chat markers, and each
  immediate second poll was empty.
- The player action menu is misleading on this build: its bundled JavaScript
  posts to `/current/players/data`, which remains on the legacy handler.
  `whisper` was submitted with a harmless marker but fell through to an
  ordinary kick. Source inspection explains this behavior. The mock contract
  now records the browser-wire behavior as authoritative.

### Resume with

1. Have both controlled players join or remain connected. Confirm they can
   report visibility of the next WebAdmin-originated all-chat and team-chat
   messages.
2. Do **not** use the browser-shaped `/current/players/data` route for
   `kickfromrole`, team swap, tracking, membership, alias/note, or whisper:
   on this build it kicks the target. Its completed failed fixture is retained
   as evidence but is deliberately excluded from the validated fixture set.
3. The controlled player currently renders as tracked and has an existing
   tracking-table entry, but exposes neither `enabletracking` nor
   `disabletracking`; do not alter that pre-existing record. Record this as a
   tracking precondition unavailable rather than manufacturing a new baseline.
4. Run `tools/webadmin_chat_send_probe.py`, which sends `wa` to all chat and
   `wt` to team `0`; collect visibility reports from both players. Then retest
   direct-form `swapteam`. Defer remaining Phase 4 role/whisper paths until
   their role or recipient preconditions exist. Every disruptive test still
   requires a fresh human reconnect checkpoint.

The current validated checkpoint fixture sets include `phase4-player-readonly`,
`phase4-player-actions`, `phase4-banid-roundtrip`,
`phase4-post-banid-reconnect`, `phase4-player-form-membership`,
`phase4-tracking-alias-roundtrip`, `phase4-tracking-note-roundtrip`, and
`phase4-player-form-swapteam`, and `phase5-two-player-readonly`. The raw
server log remains operator-only and is not a repository fixture.

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

This is an estimated **80–110 stateful scenarios**, not 80–110 individual
requests. A scenario normally means baseline read, operation, readback,
cleanup, and final readback.

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
3. Use `RUN_MARKER` in every disposable policy entry, note, alias, map list,
   campaign object, or workshop test object.
4. Immediately restore bans, session bans, policies, membership/tracking data,
   map selection, settings, and configuration changes. Verify restoration with
   a fresh GET, not merely the POST response.
5. If cleanup fails or its outcome is unknown, stop all further mutations,
   inspect the live state, restore it manually, and record the incident. Do
   not continue on the assumption that cleanup succeeded.
6. Do not test arbitrary console commands, real Workshop downloads, shared-IP
   bans, production credentials, or destructive campaign reset unless the
   human explicitly authorizes that exact operation and has a restore plan.
7. Keep the baseline plaintext-auth and MultiAdmin/SHA-1-auth test passes
   separate. Record the active authentication mode in every fixture index.
8. Treat a timed map change as an external interruption. Refresh `/current`
   before a multi-request mutation, do not start one near the end of a round,
   and re-authenticate/re-establish state if travel occurs during a sequence.

## Standard sequence template

Use this template for every numbered scenario below.

1. **Agent:** identify the exact endpoint, form, expected source/template
   behavior, sanitization rules, and cleanup operation before making a write.
2. **Agent:** capture a sanitized baseline GET and assert any precondition.
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

## Phase 7 — Evidence integration and exit criteria

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
