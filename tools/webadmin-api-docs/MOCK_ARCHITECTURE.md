# Preliminary Mock Architecture

**Status:** Preliminary architecture choice; boilerplate implemented
**Date:** 2026-10-01 (UTC)

The future RS2 WebAdmin mock will use **Sanic** as its web framework and
**Jinja** for rendering WebAdmin-compatible HTML and HTML fragments.

The initial standalone implementation lives in the sibling
[`webadmin-mock-server`](../webadmin-mock-server/) package. Its
[`ARCHITECTURE.md`](../webadmin-mock-server/ARCHITECTURE.md) records the
implemented boilerplate boundary and deferred behavior.

The mock is a deterministic, in-memory test server. A test seeds its runtime
state before startup; restarting the mock discards that state. It does not
require UE3 gameplay, a database, persistence, background workers, or a real
Rising Storm 2 server.

## Compatibility surface

The WebAdmin-compatible routes are the product contract. They must reproduce
the observed wire behavior in this repository, including legacy behavior where
it is inconvenient or inconsistent:

- HTML full pages and form submissions
- HTML fragments such as chat and map-change refresh responses
- legacy XML responses where observed
- cookies, sessions, redirects, authentication boundaries, and content types
- documented request fields, state transitions, errors, and cleanup semantics

Jinja templates should be rendered exclusively from a seeded in-memory server
state. Route handlers should translate form/query input into documented state
transitions, then render the resulting state. Reuse templates or response
helpers for the common legacy document shell, messages, and authentication
responses.

## Optional debug panel

An optional non-WebAdmin debug panel may be mounted under a clearly separate
path such as `/__debug__/`. It is not part of the compatibility contract and
may use HTMX and modern UI/design practices freely.

The debug panel may expose test-oriented controls and views for seeded players,
chat, bans, policies, sessions, and recent mock requests. It must not alter the
semantics or response shapes of the WebAdmin-compatible routes.

The boilerplate implements an opt-in dashboard, player table, safe state
inspector, request inspector, and HTMX no-op feedback controls. It does not yet
implement debug mutations or WebAdmin-compatible state changes.

## Deliberate exclusions

FastAPI, OpenAPI generation, and Pydantic request models are not selected for
the compatibility surface at this stage. They may be introduced later for a
separate developer-only interface if they provide a clear benefit, but they
must not become a requirement for emulating the legacy WebAdmin protocol.
