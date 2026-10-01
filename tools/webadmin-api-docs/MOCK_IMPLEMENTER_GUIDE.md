# Mock Implementer Guide

**Status:** Preliminary guide  
**Date:** 2026-10-01 (UTC)

Start the mock from the observed contract, not from UnrealScript alone. The
mock must reproduce the documented WebAdmin HTTP behavior for `rs2wapy` tests;
it does not need UE3 gameplay, a database, persistence, or a running RS2
server.

## Recommended reading order

1. Read [protocol.md](protocol.md) for redirects, cookies, authentication,
   session lifetime, content types, and failure behavior
2. Read [contract.yaml](contract.yaml) and the linked normalized fixtures for
   endpoint inputs, response shapes, and state transitions
3. Use [api-reference.md](api-reference.md) for route-family context and
   [rs2wapy-coverage.md](rs2wapy-coverage.md) to prioritize client behavior
4. Consult [bundled-client-assets.md](bundled-client-assets.md) for template
   and JavaScript evidence, and the licensed SDK only to find candidates or
   explain legacy behavior
5. Check [EXPERIMENTAL_DISCOVERY_RUNBOOK.md](EXPERIMENTAL_DISCOVERY_RUNBOOK.md)
   before treating incomplete or source-only behavior as supported

Live-verified contract entries and fixtures are the compatibility authority.
Bundled assets and UnrealScript sources are useful supporting evidence, but
they do not override the live server's observed behavior.

## Build order

Use the agreed **Sanic + Jinja** architecture described in
[MOCK_ARCHITECTURE.md](MOCK_ARCHITECTURE.md).

1. Model a seeded, in-memory server state and discard it on restart
2. Implement the base path, login/logout, cookie/session behavior, common
   messages, and shared HTML shell
3. Add static assets and Jinja templates or response helpers for the exact
   documented HTML, fragments, XML, redirects, and content types
4. Implement endpoint families in `contract.yaml` priority order, translating
   form input into documented in-memory state transitions
5. Add a separate optional `/__debug__/` panel only after compatibility routes
   work; it may use modern UI techniques but must never change WebAdmin routes

The mock can be developed solely from this repository's documentation and
fixtures. Optional source data improves template and source exploration but is
not a runtime dependency.
