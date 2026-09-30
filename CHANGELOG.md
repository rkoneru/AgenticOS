# Changelog

## Phase 2 - 2026-10-01 - Governed kernel (core loop)

- **ABL compiler + linter** (`@axis/abl`), **policy compiler** (`@axis/policy`: DSL to Rego, Wasm bundles, opa-backed golden cases),
  **Risk Kernel** (`@axis/risk-kernel`: gRPC `GateService`, in-process Wasm policy, kill-switch / staleness / amount / target /
  budget / rate gates, fail-closed on every error path), **audit service** (`@axis/audit`: Postgres hash chain, signed checkpoints,
  WORM export), **Python runtime** (process model, event sourcing, replay, guarded executor, gRPC gate client, Temporal workflow),
  **ModelGateway** (six provider adapters, BYO keys, endpoint SSRF guard, per-tenant breakers), and the **e2e core loop** test.
- Independent reviews found and we fixed: a raceable target cap (now atomic reserve + rollback), deny rules skipped on missing data
  (now three-valued semantics), a JS-vs-RE2 regex mismatch, unaudited DENY paths for hostile contexts, a tool kill-switch bypass,
  counter-key collisions, a bypass test that missed ~35 real bypasses (now an allowlist scanner with 169 probes plus an audit-hook
  test), platform-key exfiltration via ABL endpoints, and a cross-tenant circuit breaker. Real Temporal runs exposed three more bugs.
- **Not built / not verified** (see `docs/NEEDS.md`): Redis state and cross-instance kill-switch propagation (#18), durable Postgres
  run log (#19), KMS signer and S3 Object Lock (#12-14), live provider calls (#15), a real Temporal cluster (#17), connect-time DNS
  pinning (#22), CI has never run on GitHub. `make dev` (docker compose) is unverified (no Docker daemon here).
- Measured (in-process, in-memory stores): policy decision p99 0.055 ms, full gate p99 0.124 ms (`pnpm --filter @axis/risk-kernel bench`).

## Phase 1 — 2026-09-30 — Contracts (frozen)

- ABL v1 JSON Schema + spec + valid/invalid examples; Policy DSL v1 schema + spec; process model, IPC envelope;
  audit event schema + hash-chain reference (`@axis/contracts`); gRPC protos (`proto/axis/runtime/v1`); OpenAPI 3.1 `/v1`.
- Postgres schema (tenancy, runs/processes/event log, approvals, kill-switches, budgets, audit, pgvector memory) with forced
  RLS on every tenant table, DB-enforced append-only audit chain, migration runner with checksum immutability.
- ADRs 0003-0007 (Fastify, OPA embedded Wasm + sidecar, gVisor default, tenancy/RLS, freeze mechanism).
- Independent review amendments (ADR-0008, migration 0004): fixed a `pg_temp` search_path bypass of the audit chain guard,
  made audit hashes reproducible from DB rows, added DB state guards, stated trust boundaries (tamper-evident not
  tamper-proof; tenant GUC is not a defence against a compromised app session). WORM export, checkpoints, owner/admin roles,
  admin API surface are planned, not built (docs/NEEDS.md #8-11).
- Freeze manifest `packages/contracts/FREEZE.json` (test-enforced). Contracts derive from the master prompt only;
  the original kernel/docs were never supplied (docs/NEEDS.md #1).

## Phase 0 — 2026-09-30

- Monorepo skeleton (pnpm/Turborepo, uv), lint/format/typecheck/coverage tooling, CI workflow, compose dev stack,
  governance docs, ADR-0001/0002, inventory.
- Not verified: `make dev` (no Docker daemon in build sandbox), remote CI run.
