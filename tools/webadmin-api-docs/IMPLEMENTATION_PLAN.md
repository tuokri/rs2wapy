# RS2 WebAdmin API Documentation and Mock Contract

## Summary

Create `rising_storm_2_modding/webadmin-api-docs/` without modifying the SDK
or `rs2wapy`. Treat the reachable WebAdmin instance (UnrealEngine IpDrv Web
Server build 7258) as the only compatibility target; use the SDK to discover
candidates, but document only behavior exposed or verifiable on that server.

Deliver a human-readable Markdown reference, a machine-readable YAML mock
contract, sanitized request/response fixtures, and a standalone repeatable
probe tool.

## Discovery and Evidence Collection

- Add a standalone Python probe under the documentation directory. It will
  accept base URL and credentials only through command-line options or
  environment variables, maintain a cookie jar, implement the tokenized login
  flow selected by the server's advertised hash algorithm (the target uses
  plaintext `password` and an empty `password_hash`), and never persist
  credentials.
- Crawl the authenticated navigation and active routes, then inspect forms,
  controls, redirects, response headers, HTML fragments, AJAX endpoints,
  pagination, error states, and logout/session-expiry behavior. Cross-reference
  each discovered route to its SDK handler and to async `rs2wapy` commit
  `0ead47173da886996d366362f6bc5cf9867c3e5a`.
- For writes, snapshot affected state first; use uniquely identifiable
  disposable test records; assert the result; restore the snapshot in `finally`
  cleanup. Exercise player-targeting operations only with a controlled test
  player; if unavailable, record the prerequisite as unavailable rather than
  acting on incidental players.
- Avoid intentional invalid-password attempts because the server rate-limits
  failed authentication. Test safe negative cases through missing or expired
  sessions, invalid form tokens, malformed non-destructive inputs, unavailable
  routes, and validation failures.

## Documentation and Contract

- Write a protocol guide covering base-path redirects, connection and header
  behavior, cookies, session lifecycle, authentication inputs and hashing, form
  token handling, authorization, logout, content encodings, and error or
  redirect semantics.
- Write an API reference organized by live route family: server/current game,
  players/squads/chat, map change and map cycles, policy/moderation, settings,
  console, campaign, workshop, and any active dynamic menu routes.
- Add `contract.yaml` as the mock-oriented interface: endpoint path and verbs,
  authentication requirements, request parameters/form encoding, response
  status/headers/DOM schema, state transitions, pagination, failure cases,
  source evidence, fixture links, and mock priority. Use explicit verification
  labels (`live-verified`, `prerequisite-unavailable`, `not-exposed`) so
  unsupported SDK features are not presented as server behavior.
- Add an `rs2wapy` coverage matrix mapping each async public operation and
  parser dependency to contract endpoints and fixtures, distinguishing
  implemented, partially implemented, and currently unimplemented client
  behavior.
- Commit only normalized fixtures. Replace cookies, credentials or hashes, form
  tokens, player identifiers/keys, timestamps, server-specific names, and
  addresses with stable placeholders; retain raw captures only in a gitignored
  temporary location.

## Verification

- Add offline checks for fixture sanitization, login/form parsing, contract
  schema validity, and consistency: every documented endpoint has contract
  metadata; every contract endpoint has a source of evidence; every async public
  `rs2wapy` operation is mapped.
- Run a live capture/verification pass that compares observed status, headers,
  key DOM structures, and state transitions against the contract, then verifies
  snapshots were restored after write tests.
- Acceptance criteria: the API document is sufficient to implement a stateful
  HTML-form mock; fixtures are deterministic and secret-free; the documentation
  identifies all active route families and uncertainty caused by missing live
  prerequisites; no UnrealScript or `rs2wapy` files change.

## Assumptions

- The supplied development server is authorized for full request testing and is
  the ground truth.
- Documentation uses a configurable `{{BASE_URL}}`, not a hardcoded server
  address.
- Features visible only in SDK sources but absent from the live server are
  excluded from the supported mock contract.
