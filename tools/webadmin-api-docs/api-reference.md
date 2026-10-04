# API Reference

All paths below are relative to `/ServerAdmin/`. The application is an
authenticated HTML form interface, not a JSON API. Unless stated otherwise,
routes return `200 text/html`; a mock must return the documented DOM shape.

## Compatibility baseline

| Property | Observed behavior |
| --- | --- |
| Server | `UnrealEngine IpDrv Web Server Build 7258` |
| Application root | `/` redirects to `/ServerAdmin/`; authenticated app root redirects to `/current` |
| Login hash mode | Baseline: `hashAlg = ""` and plaintext password. MultiAdmin profile: `hashAlg = "sha1"`, accepts browser SHA-1 and plaintext fallback forms. |
| Cookie | quoted `sessionid`, path `/ServerAdmin/` |
| Logout | Session-only login serves Login after redirect. A remembered MultiAdmin login is reauthenticated by retained `authcred`/`authtimeout` cookies. |
| Transport | HTTP, `Connection: Close` on observed responses |
| Content | full XHTML-like HTML pages, HTML fragments, XML-like `<request>` action responses, or plain text |

`/policy/hashbans` returns a rendered `404` page in both observed profiles.
`/multiadmin` is a rendered `404` in the plaintext baseline but is exposed
when MultiAdmin is enabled.

## Session and utility routes

| Route | Method | Result |
| --- | --- | --- |
| `/` | GET | Creates/reuses a session. Unauthenticated response is the login page; authenticated response redirects to `/current`. |
| `/` | POST | Login form. Required fields are `token`, `username`, and either `password` or `password_hash`; optional `remember` controls persistent auth cookies. |
| `/logout` | GET | Invalidates the current session and redirects to the login page. |
| `/about` | GET | Public-looking About page after normal session/user handling. |
| `/data` | GET/POST | XML-like `<request><messages><![CDATA[...]]>` response. Without `type`, it reports `Requested unknown data type:`. The SDK handles `gametypes`, `maps`, and `mutators` types. |

Unauthenticated access to any protected route returns the login page with 200,
not HTTP 401. A mock should perform authentication before route dispatch.

The `data` endpoint was live-verified with `type=gametypes`,
`type=maps&gametype=ROGame.ROGameInfoTerritories`, and
`type=mutators&gametype=ROGame.ROGameInfoTerritories`. Each returns XML-like
elements for its selected data. `type=maps` with no game type returns a broad
map list; an unknown type returns an XML `<messages>` error. Authenticated
`/current/` and `/current/unknown-child` return rendered 404 pages.

## MultiAdmin

This conditional route exists only with MultiAdmin enabled.

| Route | Method and fields | Response / mock behavior |
| --- | --- | --- |
| `/multiadmin` | GET; POST `adminid` selects an existing account | Administrator overview with enabled/disabled CSS classes. Selecting an account displays `displayname`, `enabled`, `order`, `allow`, and `deny` fields plus a navigation preview. The selected account details are a read-only observation until `action=save` is posted. |
| `/multiadmin` | POST `action=create`, `adminid`; POST `action=save`, profile fields | `action=save` was live-verified on a disposable account and restored. Empty password fields preserve the password. `action=create` remains source-visible only. |

The observed enabled secondary account was able to read Current, Players,
Policy, General Settings, Console, and MultiAdmin. The observed disabled
account rejected a correct SHA-1 login with the normal `Invalid credentials.`
login page. A temporarily enabled restricted account received 200 for
`/current`, `/policy/session`, and `/settings/general/welcome`, while
`/settings/gametypes` and `/multiadmin` returned `403 Access Denied` pages.
Disabling that account did not invalidate its already-authenticated session;
that session still read `/current` successfully. The account's original
disabled state, allow/deny rules, display name, and password were restored.

## Current game, players, and chat

| Route | Method and fields | Response / mock behavior |
| --- | --- | --- |
| `/current` | GET; query sort fields include `sortby` and `reverse` | Current-game page: map/rules, current-player summary, `#players` table, notes form, and navigation. The RS2 template's player table renders team, role, score, kills, deaths, K/D ratio, ping, admin, and spectator state. With an immediately captured same-team/squad baseline and autobalance disabled, one controlled team kill added one rendered death and did not add a rendered kill; the apparent killer score fell by 10. This is server/profile-specific evidence, not a general score formula. `action=resetCampaign` is source-visible. |
| `/current/data` | POST `ajax=1`; `action=save`, `notes`, or `action=resetCampaign` | `text/xml` `<request><messages><![CDATA[...]]>`. Saving notes was live-verified with a fresh-page readback and restoration; non-empty line storage is rendered with a trailing newline. A bare GET is unsafe on this server; mock the AJAX form path. |
| `/current/players` | GET; POST `action`, `playerkey`; direct `whisper` also uses `__Input`; `makemember` additionally uses `__ExpNumber`, `__ExpUnit`, and `__IsAdmin` | `#players` table with player identity/status columns and per-row hidden `__PlayerId_N`, `__PlayerKey_N`, `__PlayerName_N`, and selected `__Action_N`. A direct form POST is a different wire contract from `/current/players/data`: a controlled `makemember` created a one-hour non-admin membership, returned full HTML with a success message and `cancelmembership` action, and a direct `cancelmembership` POST restored the members page and action menu baseline. Direct `swapteam` requests in both one- and two-player states returned normal HTML but left the controlled player's rendered team unchanged. A direct `whisper` with `__Input` reached the controlled recipient and did not disconnect them. A direct `kickfromrole` against an occupied commander role returned legacy wording that says removal occurs on the next death, yet the controlled client immediately returned to role selection as a grunt while both players stayed connected. The SDK calls immediate role-kick enforcement for ordinary roles; only a flying helicopter pilot waits until a safe landing/bail-out. Model this dynamic form handler separately from the browser AJAX path. |
| `/current/players/data` | POST `ajax=1`, `action`, `playerkey`; moderation actions accept `__Reason`, optional `__NotifyPlayers=1`; `banid` also accepts `__ExpNumber`, `__ExpUnit` | XML `<request>` with one of `<nop/>`, `<kicked playerkey="..."/>`, or `<text playerkey="..." label="..."/>`, plus messages. The bundled player client sends only these three base fields even though its enclosing form has additional hidden values. Its `<kicked>` handler removes the matching row; `<text>` relabels `toggletext`. `mutevoice` and `unmutevoice` were live-verified and return `<nop/>` with a success message. A syntactically plausible nonexistent player key with `action=kick` returned `<nop/>` and left both controlled players connected. A controlled two-player kick removed only the target row; the observer remained connected, and both were readable after the target manually reconnected. A controlled two-player `sessionban` likewise removed only the target, created then revoked its session-ban record, left the observer present, and allowed the target to reconnect. A two-player `banid` returned `<kicked>` and its removal message, while an immediate full player-table GET still listed the target; the observer remained present, cleanup completed, and both players were readable after the manual reconnect. Model that full-table read as potentially stale and use the XML action result for browser row removal. **Compatibility quirk:** the RS2 dynamic handler advertises extended actions (role kick, tracking, membership, alias/note, whisper, team swap) on `/current/players`, but the bundled browser posts to `/current/players/data`, which is served by the legacy handler. There, every unrecognised action falls through to an ordinary kick. A controlled `whisper` therefore returned `<kicked>` and disconnected the player. A mock should reproduce that wire behavior, rather than implementing the advertised action at this endpoint. |
| `/current/squads` | GET/POST `action=resetsquadname`, `squadteam`, `squadnumber`, `squadname` | Renders squad forms. A controlled custom-name reset was live-verified; it changed the rendered name, but WebAdmin exposes no rename/restore action, so restoration required the human game client. Treat reset as irreversible through this API. The bundled client posts AJAX to `/current/squads/data`, but that authenticated route returned the normal full-HTML 404 page on this server; use the direct form route. |
| `/current/chat` | GET or POST `message`, `teamsay`, optional `rnd` | Full page with `#chatlog`, `#chatform`, message maximum length 259, and teams `-1` (all), `0` (North), `1` (South). WebAdmin-originated all-chat was visible to both controlled clients; a team-0 post was visible only to the controlled client on team 0. |
| `/current/chat/data` | GET/POST `ajax=1`; post additionally uses `message`, `teamsay` | HTML fragment containing `.chatmessage` entries. Posting also broadcasts and advances session chat history. In two independently created sessions, human all-chat markers arrived in the same newest-first order; human team-chat markers were absent from both admin polls, and the immediate second poll in each session was empty. The bundled browser polls with POST `ajax=1` only and retains the most recent 50 rendered messages; that retention is client-side, not a server truncation guarantee. |

The chat page advertises `chatRefresh = 5000`. A mock should retain per-session
chat cursor state so a subsequent data poll can return only unseen messages.

## Map and workshop management

| Route | Method and fields | Response / mock behavior |
| --- | --- | --- |
| `/current/change` | GET; POST `action=update` or `action=change`, `gametype`, `map`, `mutatorGroupCount`, `mutgroupN`, `urlextra` | Change-map page. `action=update` refreshes the rendered map/mutator selection. `action=change` starts server travel and returns a full changing-game page with the constructed URL. A live empty-server round trip travelled to a different map in the same game type, then restored the exact game/map/mutator/URL-extra selection. `urlextra` rejects password and port fields in the UI. |
| `/current/change/data` | POST `ajax=1`, `gametype`, optional `mutatorGroupCount`, `mutgroupN` | HTML fragment with `<select id="map">`, `<div id="mutators">`, and hidden `#mutatorGroupCount`. All six live game-type choices were verified. An empty game type returns an empty select, no-mutators message, and count `0`. The bundled client sends checked mutator fields only and enforces radio-group and shared-value selection rules before this request. |
| `/current/change/check` | GET | Plain `ok` when no travel is pending; a controlled travel produced four `503 Service Unavailable` responses before `ok`. Travel expires a session-only login; remembered credentials establish a replacement session on the first successful post-travel request. |
| `/current/workshoptool` | GET/POST | Steam Workshop tool. Exposed controls include `action`, `add`, `update`, `delete`, `download`, `idx`, `steamid`, and `steamname`. It remains a full HTML page. |

For a mock, model `action=change` as a brief travelling state, emit a changing
page, make `/current/change/check` return `503` before `ok`, and invalidate
session-only authentication across the transition. In-memory state does not
need to emulate UE3 travel beyond applying the requested selection.

## Policy and moderation

| Route | Method and fields | Response / mock behavior |
| --- | --- | --- |
| `/policy` | GET; POST `action=add`, `ipmask`, `policy`; or `action=modify` with `update`/`delete` index | `#policies` table. `DENY` and `ALLOW` are the add-form values; the existing display renders `Accept`. Add/delete were live-verified using a reserved TEST-NET IP and a follow-up GET confirmed restoration. A malformed octet returns `<code>…</code> is not a valid IP mask`; an omitted policy returns `Invalid policy selected.` and neither changes state. Duplicate `ALLOW` rows are accepted. `action=modify&update=<row-index>` changed one reserved row to `DENY`; both rows were then deleted. The edit select only offers `DENY` and `ACCEPT`, so a persisted `ALLOW` row renders with neither option selected. |
| `/policy/bans` | GET/POST `action`, `uniqueid`, `playername`, `banid`; add dialog also uses `__IdType`, `__UniqueId`, `__PlayerName`, `__Reason`, `__ExpNumber`, `__ExpUnit`, optional `__NotifyPlayers=1` | Banned-ID page. The add dialog submits `action=add`; rows expose revoke/edit controls through `action` and `uniqueid`. The bundled dialog offers blank/1–12 expiry numbers and `Never`/`Hour`/`Day`/`Month`/`Year` units. A controlled `banid` with `__ExpUnit=Never` produced an active ID-ban record; `action=revoke&uniqueid=...` removed it, and the target reconnected. A no-player synthetic ID with `__IdType=0`, a reason, `__ExpNumber=1`, and `__ExpUnit=Hour` also added exactly one row and was immediately revoked back to the baseline. The active record has blank player/admin/reason/timestamp cells when no tracking entry exists. |
| `/policy/session` | GET; POST `action=revoke`, `__UniqueId`, `__Submitter` | Session-ban table. The page JavaScript posts the selected `__UniqueId` value (multiple values may be comma-separated) to revoke. A full controlled round trip was live-verified: `sessionban` created an entry and disconnected the player, then revoke returned success and a fresh GET showed no active session bans. |
| `/policy/toxicplayers` | GET/POST `action`, `playerkey`, `__PlayerName`, `__Submitter` | Toxic-player management page, including player-specific action controls. A read-only capture after reciprocal controlled enemy kills found no entries. This does not establish a team-kill threshold or toxic-player creation rule. |
| `/policy/tracking` | GET/POST `action`, `uniqueid`, `playername`, `noteid`, `details`, `__Input`, `__Text`, tab/paging fields | Tracking page with tabs, notes/details, and pagination. On a pre-existing record with an empty alias baseline, `attachalias` plus `__Input` returned a full HTML success page, rendered the alias, and replaced `attachalias` with `deletealias`; `deletealias` restored the empty-alias action set on a fresh GET. `action=showdetails` renders a JavaScript detail dialog containing `vNrOfNotes` and per-note `__DeleteNote_<id>` elements. A marker `attachnote` created exactly one note; `deletenote` with that extracted `noteid` and `details=1` restored the zero-note detail state. |
| `/policy/members` | GET/POST `action`, `uniqueid`, `membername`, `__MemberName`, `__ExpNumber`, `__ExpUnit`, `__IsAdmin`, `__CurrentTabIndex`, paging fields | Members page with tab state and row actions. A temporary membership created through `/current/players` appeared on a fresh GET and disappeared after direct `cancelmembership` cleanup. A member is keyed by game account ID, not the displayed player name: a same-name historical row did not apply to the current connection. Creating membership for the live player key, then `action=update` with `__IsAdmin=1`, followed by a manual reconnect, set the live player-table Admin flag. |

The controlled player-action probe live-verified `mutevoice`, `unmutevoice`,
the session-ban/revoke lifecycle, ordinary kick, and permanent ID-ban/revoke
lifecycle. In an earlier player state, `sessionban`
also returned `<nop/>` with the SDK's logged-admin protection. A mock should
model both branches: non-admin/developer session-ban produces a kicked response
and session-ban state; logged admin/developer targets receive an error with no
ban or disconnection. The protected branch was observed with a freshly
reconnected in-game Admin member: it returned `<nop/>`, created no session-ban
row, and left the controlled observer and target connected. Its sanitized
fixture must be rerun during a stable map state because a timed map transition
interrupted the first reproducibility pass. Role-kick remains unverified and
requires an explicitly eligible controlled player.

For ID-ban expiry, the supplied handler accepts case-insensitive `never`,
`hour`, `day`, `month`, and `year` units; an unsupported unit leaves the action
without a ban. The permanent lifecycle fixture uses `__ExpUnit=Never`.

## Settings and console

All settings pages render editable fields named `settings_<Property>` plus
companion `_label` controls. A mock should preserve submitted field names and
the page-local `action=save` response even when it stores settings in a simple
in-memory dictionary.

| Route | Important controls |
| --- | --- |
| `/settings` | Redirects to `/settings/general`. |
| `/settings/general` | Server name, advertisement interval/messages, player/network/voting/chat/VOIP settings, `liveAdjust`, `action=save`. |
| `/settings/general/gameplay` | Friendly-fire, spawn, vehicle, damage, realism and similar gameplay properties, `liveAdjust`, `action=save`. |
| `/settings/general/passwords` | Separate game (`gamepw1`, `gamepw2`) and admin (`adminpw1`, `adminpw2`) password forms. Never record submitted values. |
| `/settings/general/welcome` | `BannerLink`, `ClanMotto`, colors, `ServerMOTD`, `WebLink`, `tglWelcomeScreen`, `TBVal`, `liveAdjust`, and `action=save`. A live MOTD marker save/readback/restore preserved every other field and the enabled state. The rendered hidden `TBVal` is always `0`, even with a checked toggle; bundled JavaScript changes it to `1` before submit, and the server persists `TBVal` rather than `tglWelcomeScreen`. Server logs misleadingly report a blank `bShowWelcomeScreen` request field on these saves, so the fresh rendered page is the authoritative readback. |
| `/settings/gametypes` | `gametype`, `action=select`; per-game-type `settings_*`, `liveAdjust`, `action=save`. |
| `/settings/mutators` | `mutator`, `action=select`; selected mutator settings appear conditionally. |
| `/settings/maplist` | `maplistidx`, `gametype`, multi-line `mapcycle`; `action=save`, `delete=doit`, `activate=activate`. Exactly one active cycle is the client invariant. |
| `/settings/serveractors` | `serveractors`, `action=save`. |
| `/settings/system` | WebAdmin properties under `settings_*`, `action=save`. `/system/allowancecache` accepts `action=rebuild`. |
| `/settings/campaign` | Tab field `__CurrentTabIndex`; campaign settings use `save=save`/`resetcampaign=reset`, and campaign data uses `campaignname`, `regionCount`, `viewingTheater`, `gametype`, `save`, `delete`, `activate`, or `reset`. |
| `/console` | POST `command`; full Management Console page. `help`, `status`, and `version` were live-submitted and produced only the escaped submitted command in `#consoleResults`, no command output, and no message. The correlated server-log pass added no command-result lines. |

Persistent settings, password changes, campaign mutations, and map-cycle
writes were intentionally not executed. Their form shapes are
live-verified; model state changes from the active SDK handler only where the
contract explicitly says so.
