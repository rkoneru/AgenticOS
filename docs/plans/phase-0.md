# Phase 0 plan — Inventory and foundations

1. Inventory the repo honestly (`docs/INVENTORY.md`).
2. Merge the `CLAUDE.md` seed; add `AGENTS.md`, `SKILLS.md`, `ROUTINES.md`, `docs/NEEDS.md`, ADR-0001/0002.
3. pnpm + Turborepo + uv workspaces; lint/format/typecheck configs; pre-commit.
4. CI: lint, typecheck, test, coverage, SAST, deps, secrets, SBOM.
5. `make dev` compose stack: Postgres+pgvector, Redis, ClickHouse, Temporal(+UI), OPA, OTel collector, Jaeger, Grafana.
6. Two tiny wired packages (`@axis/shared`, `axis-runtime`) so the pipeline exercises real tests and coverage gates.

Exit: CI green on wired repo; `make dev` healthy; inventory and ADR-0001 written.
Known gap: `make dev` cannot be run in the build sandbox (no Docker daemon).
