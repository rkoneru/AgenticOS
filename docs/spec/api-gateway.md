# API gateway (`apps/api-gateway`, `@axis/api-gateway`)

Status: Prototype (built and tested in-process; dev run service; see NEEDS #215-#234). Contract: `packages/contracts/openapi/axis-v1.yaml`
(frozen v1, additive 1.1.0 by ADR 0025). Architecture: ADR 0024.

## 1. What it is

The public REST `/v1` API. It implements every operation of the OpenAPI document and nothing else; the route table and the document must
agree exactly (start-up fails otherwise, and `test/contract.test.ts` walks every operation). It fronts, in process: the control plane
(API keys, sessions, the OPA authorization pack, policy packs), the approvals service, the audit store, the billing ledger, AGIL; and
over the network: the dev run service (HTTP) and the Risk Kernel's `SetKillSwitch` (gRPC).

## 2. Request pipeline (in this order)

1. Request id (`X-Request-Id` if 8-64 safe chars, else generated) and trace id (`traceparent` if valid and non-zero, else generated);
   both are returned, the trace id is in every problem body and is the `trace_id` of the audit events and of runs the request starts.
2. Security headers, CORS headers for an allow-listed origin; `OPTIONS` preflight answered here (204, no credential needed, no headers
   for an unlisted origin). `GET /healthz` is the only unauthenticated route.
3. Route match under `/v1` (404 / 405 with `Allow`).
4. Tenant headers (`X-Tenant*`, `X-Axis-Tenant*`) are refused (400 `tenant_override`).
5. Credential: `Authorization: Bearer axk_...` (API key), `Bearer <session token>`, or `X-Axis-Api-Key`; both at once is 400. Failed
   attempts are limited per remote address BEFORE the lookup. A dependency outage is 503, never 401.
6. Per-tenant token bucket (cost-weighted per operation); `RateLimit-Limit/Remaining`, 429 + `Retry-After`.
7. Authorization: `api.<resource>.<verb>` decided by the control-plane pack (`policies/control-plane/pack.yaml`) and, for API keys, the
   scope `<resource>:read|write`. Any error is DENY (`policy_denied`); a role denial is `forbidden`. Denied mutations are audited.
8. Parameters (path, query, `Idempotency-Key`) and the body are validated against the OpenAPI schemas (ajv 2020-12, built from the
   file): unknown query parameters, a `tenant_id`-like body key, malformed JSON (400), wrong media type (415), oversize (413) are refused.
9. Idempotency (section 4).
10. Mutations are audited (ALLOW, enforcement point `admin`, action `api.<operationId>`, request trace id) BEFORE they run; if the chain
    cannot be appended the operation does not run (503).
11. Handler under a 30 s budget (504), response validated against the OpenAPI (500 + log on drift when `validateResponses`), JSON out.

The tenant is `principal.tenantId` and nothing else; no handler can read one from the request.

## 3. Operations

| Operation (`operationId`)                                     | Action                           | Backing                                                          |
| ------------------------------------------------------------- | -------------------------------- | ---------------------------------------------------------------- |
| listBlueprints, getBlueprintVersion                           | `api.blueprints.read`            | `BlueprintStore` (memory; registry later)                        |
| publishBlueprintVersion                                       | `api.blueprints.publish`         | `@axis/abl` `compileAbl` (schema + lint) then the store; 409 dup |
| listRuns, getRun                                              | `api.runs.read`                  | run service                                                      |
| startRun                                                      | `api.runs.start`                 | compiles the stored ABL to a manifest, calls the run service     |
| signalRun                                                     | `api.runs.signal`                | run service (TKI scheduler signal)                               |
| listRunEvents (JSON, or SSE with `Accept: text/event-stream`) | `api.events.read`                | run service event log / feed                                     |
| listApprovals, decideApproval                                 | `api.approvals.read` / `.decide` | `ApprovalService` (principal built from the credential only)     |
| listPolicyPacks, publishPolicyPack                            | `api.policies.read` / `.publish` | control-plane `PolicyPackService`                                |
| testPolicy (`/policies:test`)                                 | `api.policies.test`              | real `opa eval`, bounded; gates not evaluated                    |
| listAuditEvents, verifyAuditChain                             | `api.audit.read` / `.verify`     | audit store; verify range <= 50 000 events                       |
| listKillSwitches, setKillSwitch                               | `api.killswitch.read` / `.write` | kernel gRPC first, then the record store                         |
| getUsage                                                      | `api.usage.read`                 | billing ledger entries                                           |
| startEvalRun                                                  | `api.evals.run`                  | 501 until Phase 8                                                |
| explainRun                                                    | `api.explanations.read`          | AGIL over the audit trail of the run's trace                     |
| explainAuditEvent (`/audit/events/{seq}/explanation`)         | `api.audit.read`                 | AGIL                                                             |

Role matrix: `policies/control-plane/authz.cases.yaml` (`make policy-test`) and `services/control-plane/test/api-authz.test.ts`.

## 4. Idempotency, pagination, limits

- `Idempotency-Key` (8-128 chars) on POST operations that declare it. Scope = tenant + member + key. Same key and same fingerprint
  (method, path template, path params, canonical body) replays the stored response with `Idempotent-Replayed: true`; same key with a
  different fingerprint is 422; a duplicate while the first is in flight is 409; 5xx and 429 responses are not stored; deterministic
  4xx are. TTL 24 h. A replay is neither re-executed nor re-audited.
- Cursors are opaque, HMAC-bound to (tenant, resource) and tamper-evident: another tenant's or resource's cursor is 422.
- `listRunEvents.next_cursor` is the last sequence number as text (pass it as `after_sequence`).
- Defaults: body 1 MiB, request 30 s, 60-token burst at 30/s per tenant, 20 failed auths per address then 1/s, 16 SSE streams per
  tenant, SSE credential re-check every 30 s, stream ends at 15 min (resume with `Last-Event-ID`).

## 5. SSE

`GET /v1/runs/{runId}/events` with `Accept: text/event-stream`. Auth is the normal header (use `fetch` streaming; there is no token in the
URL). Existence and tenancy are checked before the stream opens. Frames: `id: <sequence>`, `event: run_event`, `data: <RunEvent JSON>`;
`: keep-alive` comments; a final `event: end` with `{"reason":"completed"|"closed"|"max_duration"|"error"}`.

## 6. Errors

`application/problem+json` as the OpenAPI `Problem`/`ValidationProblemBody`: `type` (`https://axis.example/problems/<slug>`), `title`,
`status`, `code` (closed set; omitted for 405/501), `detail`, `trace_id`, and `errors[]` (`path`, `keyword`, `message`) for validation.
Internal errors never include exception text.

## 7. Configuration (`GatewayOptions`)

`allowedOrigins`, `maxBodyBytes`, `requestTimeoutMs`, `rate`, `unauthRate`, `costs`, `maxSseStreamsPerTenant`, `sseHeartbeatMs`,
`sseRecheckMs`, `sseMaxMs`, `idempotencyTtlMs`, `validateResponses`, `behindTls`, `maxVerifyEvents`, `log`. Wiring: `wireGateway`
(`dev-wire.ts`).

## 8. Run service protocol (gateway <-> `runtime/src/axis_runtime/runserver.py`)

Bearer per tenant (token -> tenant table). `POST /v1/runs {run_id, trace_id, blueprint, manifest, input, principal}` (202, the run's
`tenant_id` is echoed so the gateway can refuse a mismatch), `GET /v1/runs[?state&blueprint&limit&cursor]`, `GET /v1/runs/{id}`,
`POST /v1/runs/{id}/signals`, `GET /v1/runs/{id}/events?after_sequence&limit`, `GET /v1/runs/{id}/events/stream`, `POST /v1/runs/{id}/replay`.
Run input text is `input.prompt|message|text` when a string, else the canonical JSON of `input`.

## 9. Tests

Contract (every operation, spec-derived), security (authn, tenant spoofing by header/body/query, IDOR on every path parameter, RBAC
matrix, audit-before-mutate), pipeline (idempotency collisions, rate-limit bypass attempts, oversize/malformed bodies, CORS), SSE, real
gRPC kernel, real run service (`runserver.integration.test.ts`), and a mutation script (`pnpm --filter @axis/api-gateway mutation`).
