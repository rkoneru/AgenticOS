# Inventory (Phase 0)

Date: 2026-09-30. Status labels: `Concept / Designed / Prototype / Built / Deployed`.

## What the brief said exists

`AXIS_MASTER_PROMPT.md` §0 and §8 assume an existing five-file Python reference kernel plus
`ARCHITECTURE.md`, `DESIGN-DECISIONS.md`, `ABL-SPEC.md` and `ROADMAP.md`.

## What the repository actually contained

At the start of Phase 0 the repo held one commit (`d071ff9`) with a two-line `README.md`.
**None of the reference kernel or the four design docs were present.** The only inputs were the
three pack files: `AXIS_MASTER_PROMPT.md`, `CLAUDE.md` (seed), `PHASE_PLAN.md`.

## Consequences

- No prior code or ABL semantics could be absorbed. `CLAUDE.md` marked the kernel "Prototype",
  TKI/Eval Hub "Prototype (standalone)" and ABL/Risk Kernel/AGIL/NEXUS "Designed". With no
  artifacts in the repo, the evidence supports only **Concept** for all of them. The status
  table in `CLAUDE.md` was downgraded accordingly.
- Core concepts (process model, fail-closed gate, ABL semantics) come from the master prompt
  alone. They will be specified from scratch in Phase 1 (ABL v1 schema, process model, policy DSL).
- If the original kernel/docs exist elsewhere, supply them. Phase 1 will reconcile them via an ADR.
  See `docs/NEEDS.md`.

## Built in Phase 0

| Item                                                        | Status    | Evidence                                                                             |
| ----------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------ |
| pnpm + Turborepo workspace                                  | Built     | `pnpm lint typecheck cov` pass locally                                               |
| uv Python workspace                                         | Built     | `uv run pytest` passes locally                                                       |
| Decision model skeleton (TS + Python, fail-closed coercion) | Prototype | `packages/shared`, `runtime/` tests                                                  |
| CI workflow                                                 | Designed  | `.github/workflows/ci.yml`; not yet run on GitHub                                    |
| docker-compose dev stack                                    | Designed  | `docker compose config` validates; never started (no Docker daemon in build sandbox) |
