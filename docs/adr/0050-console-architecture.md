# 0050. Console architecture: BFF, nonce CSP, server-side ABL validation

Status: Accepted · Date: 2026-10-02 · Related: 0021/0022 (control plane cookies and CSRF), 0007 (contract freeze)

## Context

The console must use the control plane's cookie session, keep secrets out of the browser, resist XSS from untrusted agent text, and validate ABL live with the real compiler.
`@axis/abl` reads its JSON Schema from disk, so it cannot run in a browser bundle without a fork.

## Decision

1. **Same-origin BFF** (`app/api/axis/[...path]`): browser -> console -> control plane. It allow-lists paths, checks `Origin` plus the double-submit CSRF header, forwards the session cookie, and streams (SSE). Rejected: browser-direct calls (CORS, cookie scope, wider CSP `connect-src`) and Next rewrites for everything (no CSRF hook). SSO start/callback alone use a rewrite so cookies are set for the console origin.
2. **ABL validation on the server** (`/api/abl/validate`, real `compileAbl`/`lintAbl`), mapped to line/column via the `yaml` AST. Rejected: bundling the compiler for the browser (fs schema load, doubles the surface); a custom JS validator (drift from the real compiler). Publishing still goes through `POST /v1/blueprints`, which validates again: the live check is advisory.
3. **CSP with per-request nonces and `strict-dynamic`**, no inline styles (geometry via SVG attributes), pages dynamic. `proxy.ts` (Next 16 name for middleware) also does an optimistic sign-in redirect; it is not authorisation.
4. **Role-aware UI is a hint.** Hide, never trust; e2e proves the server refuses bypasses (self-approval, CSRF, viewer actions).
5. **Local `lib/api.ts`** typed against the OpenAPI, not the SDK (built in parallel). A contract test ties it to the spec. One module so the SDK can be swapped in.
6. **Mock API for tests** that reuses the real ABL compiler and the real hash-chain reference, so the console is not tested against invented validation.

## Consequences

Console tests prove UI behaviour against the spec, not against the real gateway (NEEDS #1300). The BFF adds one hop (SSE passes through it). The mock is a second implementation of the API that must be kept honest by the spec contract test and by `make e2e-phase7` (component E).
