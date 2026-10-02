# 0024. API gateway architecture (`apps/api-gateway`)

Status: Accepted · Date: 2026-10-02 · Related: 0003 (Fastify, amended below), 0007 (freeze), 0021 (control-plane authz), 0022 (Phase 6 wiring)

## Context

Phase 7 component A: the public REST `/v1` API (the frozen `packages/contracts/openapi/axis-v1.yaml`) in front of the control plane,
approvals, audit, billing, the Risk Kernel's kill-switches and a run service. Every operation must be tenant-scoped from the
credential only, RBAC-checked, idempotent where it creates something, rate limited, validated against the OpenAPI both ways and
audited.

## Decisions

1. **Plain `node:http` + `ajv`, not Fastify (amends 0003).** Every other service (control plane, billing, memory, channels, the
   approvals dev bridge) is `node:http`; the gateway's logic is a pipeline (credential -> rate limit -> authz -> validation ->
   idempotency -> handler) that does not benefit from a plugin model, and a new framework dependency would churn the shared lockfile
   in the middle of three parallel Phase 7 components. 0003's real requirement, schema-first validation derived from the OpenAPI
   source of truth, is met by building the validators FROM the frozen file at start-up (`src/spec.ts`, ajv 2020-12), so a spec change
   is a code change by construction. A contract test walks every operation in the spec and fails when a route is missing.
2. **Ports and adapters.** The gateway depends on narrow ports (`src/ports.ts`): `Authenticator`, `Authz`, `BlueprintStore`,
   `RunsPort`, `ApprovalsPort`, `PolicyPort`, `AuditPort`, `KillSwitchPort`, `UsagePort`, `IdempotencyStore`, `RateLimiter`,
   `Explainer`. Adapters (`src/adapters/*`) wrap the real in-process services (control-plane `ApiKeyService`/`SessionService`/
   `Authorizer`/`PolicyPackService`, `ApprovalService`, an audit store, the billing ledger) or the run service over HTTP, and the
   Risk Kernel's `SetKillSwitch` over gRPC. Fakes of the ports exist for unit tests only; the integration test uses the real
   control-plane, approvals, audit and billing classes in-process.
3. **Credentials.** `Authorization: Bearer <token>` (`axk_...` API key -> `ApiKeyService.verify`, anything else -> session access
   token -> `SessionService.authenticate`) or `X-Axis-Api-Key` (the spec's `apiKey` scheme). No cookies: the gateway has no CSRF
   surface. No token in a URL (SSE uses `fetch` streaming with the header). Both headers at once is a 400. The `Principal` the
   control plane returns is the only source of the tenant: a `tenant_id` anywhere in the body's top level, any `tenant` query
   parameter, an unknown query parameter or an `X-Tenant*` header is rejected (422/400), never ignored silently.
4. **Authorization.** One `api.<resource>.<verb>` action per operation, decided by the SAME OPA pack as the admin API
   (`policies/control-plane/pack.yaml`, additive rules + a full role x action golden matrix). API keys additionally need the
   scope `<resource>:read|write`. A decision that cannot be made (engine error, timeout, missing pack) is DENY (`policy_denied`).
   Mutations are audited (allow and deny) in the tenant's chain with enforcement point `admin`, action `api.<operation>` and the
   request's trace id; if that append fails the mutation is refused (503), fail-closed. Reads are audited only when denied.
5. **Idempotency** (`Idempotency-Key`, 8-128 chars) on every POST that creates or starts something. Scope = (tenant, member, key);
   a stored entry holds the request fingerprint (method, path template, canonical body hash) and the response. Same key + same
   fingerprint replays the stored response (`Idempotent-Replayed: true`); same key + different fingerprint is 422; a concurrent
   duplicate in flight is 409; responses with status >= 500 or 429 are not stored so a retry re-executes. Entries live 24 h.
   The store is in memory behind a port (NEEDS #1006).
6. **Rate limits** are per tenant token buckets (cost-weighted: `policies:test`, audit verify, policy publish and run start cost more),
   keyed by the authenticated tenant, never by a header; failed authentications are limited per remote address. `429` with
   `Retry-After` and RFC 9239-style `RateLimit-*` headers.
7. **Errors** are `application/problem+json` (RFC 9457) carrying `trace_id`; internal errors never echo exception text.
8. **Limits**: body <= 1 MiB (413), `application/json` required for bodies (415), request time budget 30 s (504), headers/request
   timeouts on the server, at most 16 concurrent SSE streams per tenant, SSE credentials re-checked every 30 s and the stream ends at
   15 minutes (the client resumes with `Last-Event-ID`).
9. **CORS**: an exact allow-list of origins from configuration (the console origin); no wildcard, no credentials mode; preflight is
   answered before authentication and never reflects an unlisted origin. Security headers on every response (`nosniff`,
   `no-store`, `frame-ancestors 'none'` CSP, HSTS when `behindTls`, `Referrer-Policy: no-referrer`).
10. **Evals** (`POST /v1/evals/runs`) are in the contract but the Eval Hub is Phase 8: the operation is authenticated,
    authorized and validated, then answers `501` problem+json (`.../problems/not_implemented`). NEEDS #1001.
11. **Response validation** against the OpenAPI is on in development and test (`validateResponses`): a handler that returns a
    shape the contract does not allow becomes a 500 and a log line, which makes drift visible in the first test that touches it.

## Consequences

The gateway is a thin, testable pipeline over existing services. Anything that needs durable gateway-owned state (idempotency
keys, blueprints, kill-switch records, run index) is behind a port with an in-memory implementation and a NEEDS entry; the
registry component replaces the blueprint store.
