# Changelog

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
