# STRIDE: API gateway, run service and AGIL

Status: Prototype (standalone dev composition). Earlier model with 14 numbered threats: [api-gateway-threat-model.md](api-gateway-threat-model.md).

## Assets

- Tenant isolation at the public API, role and scope enforcement, idempotency of mutations.
- Credentials in transit (API keys, sessions, per-tenant service tokens), audit integrity, kill-switch availability.
- The Eval Hub tenant API and runner surface hosted by the same process.

## Trust boundaries

1. Internet client (untrusted) to the gateway: credential authentication, size and time limits, exact-origin CORS (`apps/api-gateway/src/server.ts`, `apps/api-gateway/src/limits.ts`).
2. Gateway to ports (run service, kernel kill applier, blueprint store, control plane, hub): every port call is tenant-scoped; answers for another tenant are refused (`apps/api-gateway/src/ports.ts`, `apps/api-gateway/src/adapters`).
3. Gateway to the run service over loopback HTTP with a bearer per tenant (`runtime/src/axis_runtime/runserver.py`).

## Data flow

Request -> limits -> credential -> tenant from the credential only -> RBAC and key scopes (OPA pack per `api.*` action) -> idempotency -> mutation audited BEFORE it runs -> port call -> response validated against the OpenAPI schema -> problem+json without internals on error.

## STRIDE

| Category | Threat | Mitigation (code path) | Test | Residual / NEEDS |
| --- | --- | --- | --- | --- |
| Spoofing | Tenant named in header, body, query or cursor | Tenant only from the credential; `X-Tenant*` is 400, `tenant_id` in a body 422, cursors HMAC-bound to tenant and resource (`apps/api-gateway/src/context.ts`) | `apps/api-gateway/test/security.test.ts`, `e2e/redteam_probes.py` | none known |
| Spoofing | Credential guessing | Failed-auth bucket per remote address checked before lookup; uniform 401 (`apps/api-gateway/src/limits.ts`) | `apps/api-gateway/test/hardening.test.ts` | No trusted-proxy handling (NEEDS #221) |
| Tampering | Replay or double execution of a mutation | Idempotency keys scoped to tenant and member, fingerprinted, 24 h, in-flight 409 (`apps/api-gateway/src/routes.ts`) | `apps/api-gateway/test/pipeline.test.ts` | In-memory store (NEEDS #220) |
| Tampering | Request smuggling to the run service | Chunked bodies refused, Content-Length only, header caps, bearer per tenant (`runtime/src/axis_runtime/runserver.py`) | `runtime/tests/test_runserver.py` | Plain loopback HTTP (NEEDS #230) |
| Repudiation | A mutation that left no record | Mutation audited before it runs; an audit failure refuses it; request trace id equals the run trace id (`apps/api-gateway/src/routes.ts`) | `apps/api-gateway/test/pipeline.test.ts` | Granted reads are not audited |
| Information disclosure | IDOR on run, approval, blueprint, audit ids | Every port is tenant-scoped; foreign ids answer like missing ones (`apps/api-gateway/src/ports.ts`) | `apps/api-gateway/test/security.test.ts`, `e2e/test_phase7_interfaces.py` | Store bugs behind a port |
| Information disclosure | Leaks in errors or extra fields | problem+json without exception text; response validation (`apps/api-gateway/src/problem.ts`) | `apps/api-gateway/test/contract.test.ts` | PHI in run event data (NEEDS #229) |
| Denial of service | Resource exhaustion | Body 1 MiB, request 30 s, per-tenant buckets with costs, SSE caps, `opa` concurrency cap (`apps/api-gateway/src/limits.ts`) | `apps/api-gateway/test/hardening.test.ts` | Per process limits (NEEDS #221) |
| Denial of service | Stolen or revoked credential on a long stream | SSE re-checks the credential every 30 s (`apps/api-gateway/src/server.ts`) | `apps/api-gateway/test/security.test.ts` | Up to one interval (NEEDS #227) |
| Elevation of privilege | Role or scope escalation | OPA pack per action, key scopes, role ceilings, fail-closed on authz error (`apps/api-gateway/src/spec.ts`) | `apps/api-gateway/test/security.test.ts`, `e2e/test_phase7_interfaces.py` | Pack authoring errors (NEEDS #208) |
| Elevation of privilege | AGIL influencing a decision | Read-only reader, import lint, narrator input is an enumerated projection (`services/agil/src/explain.ts`) | `services/agil/test/architecture.test.ts` | none |

## Prompt injection

The gateway carries user text and run output as data and never interprets it. Two places could carry an injection into a decision, and neither does: AGIL's explanations are derived from audit rows and sanitised (`services/agil/src/sanitize.ts`, `services/agil/test/explain.test.ts`), and an SSE consumer receives event data as inert JSON. The red-team probes run against this gateway with a foreign key, a forged key, a narrow key and tenant hints in query and header (`e2e/redteam_probes.py`).

## Tool misuse

An agent holding an API key as a tool would be limited by key scopes and role ceilings, and a mass-assignment attempt is rejected by strict schemas (unknown query parameters 422, body tenant 422). Kill-switch endpoints refuse a `global` scope for tenant credentials (probe `rt-px-p09` in `e2e/redteam_probes.py`).
