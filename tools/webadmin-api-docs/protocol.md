# WebAdmin Protocol

## Base URL and path handling

The baseline server listens over HTTP. A request to `/` returns `302 Document
Moved` with `Location: /ServerAdmin/`. The WebAdmin application lives under the
trailing-slash base path `/ServerAdmin/`; clients should preserve that slash
when resolving relative URLs.

Every observed request returns `Connection: Close`. Clients and mocks must not
depend on persistent TCP connections.

## Session and authentication

1. `GET /ServerAdmin/` creates a session and sends a `sessionid` cookie scoped
   to `/ServerAdmin/`.
2. The unauthenticated HTML page contains hidden `token` and `password_hash`
   fields plus `username` and `password` controls.
3. Form authentication is an `application/x-www-form-urlencoded` `POST` to
   `/ServerAdmin/`. The baseline login page advertises `hashAlg = ""`, so it
   accepts the plaintext `password` field and an empty `password_hash` field.
   The same SDK supports a `hashAlg = "sha1"` variant, where the browser
   submits `password_hash=$sha1$<sha1(password + username)>`, clears
   `password`, and includes the per-session `token`. The mock target is the
   observed plaintext variant.
4. Subsequent requests must send the `sessionid` cookie. A successful session
   is authenticated until logout or server-side expiration. If the login form's
   optional `remember` field is used, the server may additionally issue
   `authcred` and `authtimeout` cookies.
5. `GET /ServerAdmin/logout` destroys the session, expires authentication
   cookies, and redirects to the base application path.

An unauthenticated request to an application route returns the login HTML with
HTTP 200 rather than a route-specific 401 or 404. Route existence must
therefore be determined after successful authentication.

Do not intentionally submit wrong passwords during automated discovery. The
source defaults the per-IP failed-login threshold to five attempts.

### MultiAdmin/SHA-1 profile (live verified)

With MultiAdmin enabled, the login page advertises `hashAlg = "sha1"`. Browser
compatible authentication sends `password_hash=$sha1$<SHA1(password + username)>`
and an empty `password`; this flow was accepted. The same live profile also
accepted a plaintext `password` with an empty `password_hash`, so a mock must
support both accepted wire forms when this profile is selected.

An authenticated login with `remember=1800` sets `authcred` and `authtimeout`
cookies at `/ServerAdmin/` with a 1800-second lifetime. Logging out destroys
the session, but a client retaining those remembered cookies is immediately
authenticated again on the redirected request. By contrast, a session-only
login becomes unauthenticated after logout. Two independent session-only
cookie jars remain isolated when one logs out.

The MultiAdmin profile still returns the login page with HTTP 200 for
unauthenticated protected routes. Empty login fields return that page without
an error message; a valid hash submission with no token returns `Invalid form
data.` before credential authentication.

MultiAdmin path rules are enforced as `403 Access Denied` full HTML pages for
an authenticated restricted user. Changing an account from enabled to disabled
does not revoke an already-authenticated session: the existing session remained
able to read `/current` after the profile was restored to disabled. A new login
for the disabled account is rejected with `Invalid credentials.`

## Request conventions

- Page reads are generally `GET` requests.
- Actions are submitted as URL-encoded form fields to the page URL, including
  `action` and page-specific fields.
- AJAX fragments use the same routes with an `ajax=1` field. They commonly
  return HTML fragments rather than JSON.
- Notes save through `POST /current/data` with `ajax=1`, `action=save`, and
  `notes`; the `#notesForm` HTML action is progressively enhanced by the
  bundled JavaScript. The server stores notes as lines and renders a trailing
  newline after each non-empty line.
- Chat requests require `X-Requested-With: XMLHttpRequest` in browser-like
  clients. The existing client also supplies normal browser `Accept` and
  `Referer` headers.
- The server accepts `gzip` only when requested. The probe deliberately avoids
  compression so fixtures contain decoded HTML.

## Response conventions

Responses are HTML or HTML fragments with `Content-Type: text/html`; endpoint
schemas are defined by DOM elements, form field names, table rows, and select
options. A mock must preserve the selectors consumed by `rs2wapy`, including
the empty-table and pagination variants.

The console is a full HTML response. It echoes a submitted command in
`#consoleResults`, but `help` and `status` produced no returned command text.
This is compatible with its UI warning that a command may execute without
returning information. A second controlled pass of `help`, `status`, and
`version` also produced no corresponding command-result lines in the server
log. A mock should make the submitted command observable in the page, but need
not synthesize engine output by default.

During seamless server travel, any route can respond with `503 Service
Unavailable` and a refresh page. A controlled travel produced four initial
`503` responses from `/current/change/check`, then plain `ok` after the new
map loaded. Travel invalidated the session-only `sessionid`; a remembered
`authcred`/`authtimeout` login established a new session on the first successful
post-travel request. Mocks should model that session boundary as well as the
transient `503` state.

## Fixture normalization

Sanitized fixtures replace host-specific or credential-equivalent values with
placeholders, including `{{BASE_URL}}`, `{{SESSION_ID}}`, `{{AUTH_CRED}}`,
`{{AUTH_FORM_TOKEN}}`, `{{PLAYER_ID}}`, `{{PLAYER_KEY}}`, `{{UNIQUE_ID}}`,
`{{ADMIN_1}}`, and `{{TIMESTAMP}}`. Raw HTTP captures must remain outside this
repository.
