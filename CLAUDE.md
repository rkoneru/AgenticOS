# CLAUDE.md — AXIS

> Working memory for Claude Code in this repo. Read this at the start of every session.
> Keep it under ~250 lines; move detail into `docs/` and link it.

## What AXIS is

An enterprise **Agentic OS delivered as SaaS**. Agents run as OS-style processes, declared in **ABL**, routed by **NEXUS**, orchestrated by **TKI**, gated by the fail-closed **Risk Kernel**, explained by **AGIL**, measured by **Eval Hub**. Closed source. Independent work — no employer code, names, or data.

Full brief: `AXIS_MASTER_PROMPT.md` · Phases: `PHASE_PLAN.md` · Architecture: `ARCHITECTURE.md`

## Invariants (never break these)

1. **Fail-closed.** Every tool, MCP, browser, code, memory-write, and outbound-message action passes the Risk Kernel. Error, timeout, or missing policy → `DENY`.
2. **AGIL never governs.** It reads from the audit log only; it is never on the decision path.
3. **Tenant isolation at the database.** Postgres RLS on every tenant table; no query path without `tenant_id`.
4. **Everything is auditable.** Append-only, hash-chained audit events with trace IDs. Runs are replayable.
5. **Provider-neutral models.** Only the `ModelGateway` talks to model providers. BYO keys per tenant.
6. **Honest status labels.** `Concept / Designed / Prototype / Built / Deployed` — evidence decides, not intent.

## Stack

pnpm + Turborepo · TS control plane (Node 22) · Python 3.12 runtime (uv) · Temporal · Next.js + shadcn console · Postgres 16 + pgvector · Redis · ClickHouse · OpenTelemetry · OPA (policy DSL compiles to Rego) · WorkOS · Stripe (usage-based) · Terraform (AWS/GCP/Azure) + Helm · docker-compose local · k3s home-lab profile

## Repo map

```
apps/        console, api-gateway, cli, docs-site
services/    control-plane, policy, registry, marketplace, billing, memory,
             channels, voice, approvals, audit
runtime/     python agent runtime, sandboxes, browser workers
packages/    abl, sdk-ts, shared types, ui kit
sdk/python/  python SDK
proto/       gRPC contracts        policies/  default policy packs
evals/       Eval Hub suites       infra/     terraform, helm, compose, k3s
docs/        adr/, plans/, compliance/, security/, runbooks/
```

## Commands

```bash
make dev            # full local stack via docker-compose
make test           # all unit + integration tests
make e2e-core       # Phase 2 core loop: ABL -> runtime -> Risk Kernel (gRPC) -> Postgres audit
make e2e            # (planned, Phase 7) Playwright + CLI e2e
make cov            # coverage report; fails under thresholds
make evals          # Eval Hub suites with CI thresholds
make lint typecheck # eslint/ruff, tsc/mypy
make policy-test    # compile YAML policies to Rego, check with opa, run golden cases (needs opa on PATH)
make k3s-up         # deploy to local/home-lab k3s
make tf-plan CLOUD=aws|gcp|azure   # plan only — never apply without me
```

(Keep this list true. If a command doesn't exist yet, mark it `(planned)`.)

## Working rules

- **Autonomous, end to end.** Don't wait between phases. Decide, write an ADR in `docs/adr/`, continue.
- **Plan mode at each phase start**; write `docs/plans/phase-N.md`.
- **Contracts first.** Proto, OpenAPI, ABL schema, DB schema are frozen before parallel work. Changes after freeze need an ADR.
- **Subagents + worktrees** for independent services after freeze. A separate review subagent audits each phase exit.
- **Coverage:** 95% on core packages (ABL compiler, policy compiler, Risk Kernel, TKI, audit, billing ledger, tenancy); 85% elsewhere.
- **Conventional commits**, small and single-purpose. Update `CHANGELOG.md` per phase.
- **Never fake done.** No stub reported as built, no skipped tests, no hard-coded eval scores. Gaps go in `docs/NEEDS.md`.

## Hard stops — pause and ask

- `terraform apply` or any action that spends money or touches a real cloud account
- Publishing packages/images publicly, DNS, domains, Stripe live mode
- Missing credentials (use fakes meanwhile; log in `docs/NEEDS.md`)

## Component status

| Component                                                             | Status                                      | Evidence                                                                                                                             |
| --------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Python reference kernel (existing)                                    | Not found in repo                           | `docs/INVENTORY.md`, `docs/NEEDS.md` #1                                                                                              |
| Monorepo, tooling, CI workflow                                        | Built (CI unrun remotely)                   | local `pnpm lint typecheck cov`, `uv run pytest`                                                                                     |
| Compose dev stack                                                     | Designed (never started)                    | `docker compose config` only                                                                                                         |
| Decision model skeleton (TS + Py)                                     | Prototype                                   | `packages/shared`, `runtime/` tests                                                                                                  |
| Process model, IPC envelope, audit event + hash-chain reference       | Built (frozen v1)                           | `packages/contracts` tests (100% cov)                                                                                                |
| gRPC + OpenAPI 3.1 contracts                                          | Built (frozen v1), no implementations       | `buf lint/build`, `redocly lint`, drift test                                                                                         |
| Postgres schema + RLS + migrations                                    | Built, tested on PG16+pgvector              | `packages/db` tenancy tests, mutation-checked                                                                                        |
| ABL v1 schema, spec, examples                                         | Built (frozen v1)                           | `packages/abl` tests, `docs/spec/abl-v1.md`                                                                                          |
| ABL compiler + linter                                                 | Built                                       | `packages/abl`: 163 tests, 100% cov, golden manifests, 10 lint rules                                                                 |
| Policy DSL v1 schema + decision model                                 | Built (frozen v1)                           | `packages/contracts` tests, `docs/spec/policy-dsl-v1.md`                                                                             |
| Policy compiler (DSL to Rego, Wasm bundles, `make policy-test`)       | Built                                       | `packages/policy`: 106 tests; Rego checked against real OPA (differential + property tests)                                          |
| Risk Kernel (gRPC, Wasm policy, 6 gate types, kill-switches)          | Built, single-instance                      | `services/risk-kernel`: 155 tests, 99.5% cov; state is in-memory (Redis stores and cross-instance kill-switch propagation NOT built) |
| Audit service (hash chain, checkpoints, WORM export)                  | Built as a library                          | `services/audit`: 71 tests on real Postgres; no network surface; KMS signer and S3 Object Lock NOT built                             |
| Python runtime (process model, event sourcing, executor, gate client) | Built                                       | `runtime/`: 690 tests, 97.9% cov, mypy strict                                                                                        |
| Temporal workflows                                                    | Built on the time-skipping test server only | `runtime/tests/test_temporal.py`; not run on a real cluster                                                                          |
| ModelGateway (6 providers, BYO keys, endpoint SSRF guard)             | Prototype                                   | fixture-tested only; no live provider call has been made                                                                             |
| Bypass guard (allowlist scanner + audit-hook test)                    | Built as a regression net                   | heuristic, not proof or isolation (`docs/NEEDS.md` #23)                                                                              |
| Phase 2 core loop e2e (`make e2e-core`)                               | Built                                       | ABL to runtime to real kernel over gRPC to Postgres audit, 8 scenarios                                                               |
| TKI                                                                   | Concept                                     | —                                                                                                                                    |
| NEXUS router                                                          | Concept                                     | —                                                                                                                                    |
| MPM                                                                   | Concept (stub planned)                      | —                                                                                                                                    |
| AGIL                                                                  | Concept                                     | —                                                                                                                                    |
| Eval Hub                                                              | Concept                                     | —                                                                                                                                    |
| Control plane / console / CLI / SDKs                                  | Concept                                     | —                                                                                                                                    |
| Voice / omnichannel / marketplace                                     | Concept                                     | —                                                                                                                                    |
| _Update this table at every phase exit._                              |

## Companion files

`AGENTS.md` (subagent roster and briefs) · `SKILLS.md` (reusable procedures) · `ROUTINES.md` (recurring checks: phase exit, release, security scan) · `docs/NEEDS.md` (blockers and credentials)
