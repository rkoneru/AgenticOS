# Changelog

## Phase 3 - Orchestration and routing (e2e integration)

- **Approvals end to end.** The Risk Kernel opens approval requests (`ApprovalRequester`), returns the id, and re-gates a signed
  APPROVED record presented by the runtime (`ApprovalVerifier`, single-use): kill-switches, DENY policies and caps still apply;
  requester failure is DENY. The runtime executor resolves the decision and re-submits (denied/expired/unresolvable/unaccepted:
  nothing runs). The approvals service shares the kernel's audit chain; a loopback dev bridge (not an approver API) connects them.
- **TKI in the run.** `RunDeps.child_spawner` / `TkiChildSpawner`: in-run children run as supervised TKI processes with ABL-driven
  budgets rolling up to the parent; a hard-cap trip ends only the offender with `budget_exceeded`. Fixed `Supervisor.settle` spinning.
- **NEXUS in the run.** `RunDeps.nexus_factory` routes every model step (cache -> rules -> llm); `nexus_stage`/`nexus_route` are
  additive run-event types (ADR 0012, no frozen contract changed); `InMemoryTracer.export()`; the cache key covers the whole
  conversation. Fixed ABL `maxOutputTokens` being ignored.
- **`make e2e-phase3`** (+ CI job): 11 scenarios against the real kernel, approvals service, Postgres audit chain, TKI, NEXUS and
  runtime: granted (request, decision, gated execution, one run), denied, expired, self-approval, cross-tenant id, bound/single-use/
  kill-switch/cap re-gate, no approvals service, multi-agent run with a capped child, stage metrics in the trace, cache hit cheaper.
- **Not built / not verified** (`docs/NEEDS.md` #62-#68): production approver API and runtime transport, durable consumed-approval
  store, approval request hygiene, gating of cache/rules hits, Temporal wiring, ledger/NEXUS events in the audit chain, no remote CI run.

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
