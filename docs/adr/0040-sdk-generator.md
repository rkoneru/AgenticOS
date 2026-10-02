# 0040. SDK generator: one script, committed output, drift test

Status: Accepted · Date: 2026-10-02 · Related: 0007 (contracts freeze), `docs/spec/sdk.md`

## Context

Phase 7 needs typed TS and Python clients for the frozen `/v1` OpenAPI. The gateway may add AGIL/registry paths additively, so regeneration must be cheap and safe.

## Decision

- `scripts/generate-sdks.mjs` (Node, uses only the repo's `yaml`) reads `packages/contracts/openapi/axis-v1.yaml` (+ the audit-event schema for `AuditEvent`) and writes, deterministically and without network:
  `packages/sdk-ts/src/generated/{types,operations,client}.ts`, `sdk/python/src/axis_sdk/_generated/{models,operations,client}.py` (TypedDict models, sync + async clients) and `test/fixtures/mock-model.json` in both SDKs (the dereferenced spec the mock servers are built from).
- Every file carries `@generated ... DO NOT EDIT` plus a hash of the inputs. `--check` exits 1 on any difference; a vitest and a pytest drift test call it. Re-running after a spec change is `node scripts/generate-sdks.mjs`.
- Generated: one method per `operationId`, request/response types, an operation table (`OPERATIONS`: path, params, `idempotent` mode). Hand-written: transport, retries, errors, SSE, pagination, the `Axis` client.
- ABL and policy documents are typed as opaque objects (their schemas are validated by the ABL compiler / server, not re-modelled in the SDKs). TypedDicts instead of pydantic keep the Python SDK's only runtime dependency `httpx`. Request/response validation is off by default; TS accepts injected validators.
- Retry classification is generated: GET/PUT/DELETE are `always`, POST with an `Idempotency-Key` parameter is `with-key`, other POSTs are `never`, except an explicit allowlist of read-only POSTs (`testPolicy`, `verifyAuditChain`), because OpenAPI 3.1 cannot mark a POST as safe.
- Generated output is excluded from prettier and ruff (still type-checked by tsc/mypy).

## Consequences

A new operation without a hand-written resource method fails the "ergonomic layer reaches every operationId" tests (a typed table in both test suites), so coverage cannot silently lag the spec.
