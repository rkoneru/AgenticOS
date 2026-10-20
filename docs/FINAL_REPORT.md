# AXIS — Final Report (Phases 0-10)

Status date: 2026-10-20. This is a status snapshot of an independent, autonomous
build-through-Phase-10 pass of AXIS, written honestly per CLAUDE.md invariant 6
(`Concept / Designed / Prototype / Built / Deployed` — evidence decides, not
intent). Nothing here is rounded up. The live, line-by-line source of truth is
`CLAUDE.md`'s component table and `docs/NEEDS.md`; this document is a narrative
summary of both, plus the test/coverage/NFR numbers and the deploy commands.

## What AXIS is, in one paragraph

An enterprise Agentic OS delivered as SaaS. Agents run as OS-style processes,
declared in ABL (a schema'd agent-blueprint language), routed by NEXUS,
orchestrated by TKI (a tiny kernel interface for multi-agent spawning and
budgets), gated by a fail-closed Risk Kernel (every tool/MCP/browser/code/
memory-write/outbound-message action passes a gRPC gate; error, timeout, or
missing policy denies), explained read-only by AGIL (never on the decision
path), measured by an Eval Hub that blocks a blueprint release on an eval
regression.

## How to read "Built"

Across this project, "Built" means: real code, real tests on a real Postgres
16 (not a mock), passing a real review's adversarial pass, wired into at least
one real multi-service e2e scenario — but still running on this project's
fakes at every external boundary (IdP, KMS, DNS, model providers, Stripe,
telephony, cloud provider APIs) unless a row says otherwise. "Deployed" is
reserved for something that ran against real infrastructure this session
itself stood up and tore down, with evidence — the local k3d cluster run in
Phase 10 is the only thing in this project that earns that word, and only for
the narrow slice it actually exercised.

## Status per component (summary — CLAUDE.md is authoritative)

| Layer                                                                                                       | Status                                                                                                                                                                                                                                               | Where                                               |
| ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Contracts (gRPC, OpenAPI 3.1, ABL v1, policy DSL v1, audit event + hash chain, DB schema)                   | Built, frozen v1 (additive-only since)                                                                                                                                                                                                               | `packages/contracts`, `packages/abl`, `packages/db` |
| Risk Kernel (6 gate types, Wasm policy, kill-switches, capability classifier)                               | Built, single-instance; classifier hardened against real evasions found in review (ADR 0110, 0114)                                                                                                                                                   | `services/risk-kernel`                              |
| Audit service (hash chain, checkpoints)                                                                     | Built as a library; no KMS signer/Object Lock yet                                                                                                                                                                                                    | `services/audit`                                    |
| Python runtime (process model, event sourcing, executor, gate client, PHI net)                              | Built                                                                                                                                                                                                                                                | `runtime/`                                          |
| TKI / NEXUS / MPM                                                                                           | Built/Prototype, single-instance, in-memory state                                                                                                                                                                                                    | `runtime/`                                          |
| Approvals, Memory, MCP, Code sandbox, Browser workers                                                       | Built/Prototype, dev surfaces, sandbox is process-level isolation (not a hard security boundary)                                                                                                                                                     | `services/approvals`, `services/memory`, `runtime/` |
| Channels (6 adapters) + Voice pipeline                                                                      | Prototype against fakes; no live provider                                                                                                                                                                                                            | `services/channels`, `runtime/`                     |
| AGIL (read-only explainer)                                                                                  | Prototype, narrator off by default                                                                                                                                                                                                                   | `services/agil`                                     |
| Eval Hub + runner/graders/judge/sampler                                                                     | Prototype, scripted models, real gate enforcement                                                                                                                                                                                                    | `services/eval-hub`, `runtime/.../evals`            |
| Control plane (SSO/SCIM/RBAC/BYO keys/tenancy/budgets)                                                      | Prototype against fakes + real Postgres                                                                                                                                                                                                              | `services/control-plane`                            |
| Billing + usage ledger                                                                                      | Prototype against a Stripe fake + real Postgres                                                                                                                                                                                                      | `services/billing`                                  |
| Console + UI kit, Docs site, CLI + SDKs, API gateway, Registry + Marketplace                                | Prototype/Built, real-stack e2e suites green, dev composition only                                                                                                                                                                                   | `apps/*`, `packages/sdk-ts`, `sdk/python`           |
| Compliance (matrix, Annex IV, ISO 42001 records) + Data governance (DSAR, holds, retention, residency, PHI) | Prototype; independent review closed a legal-hold TOCTOU and a matrix symlink-evidence escape (ADR 0115)                                                                                                                                             | `services/compliance`, `services/data-governance`   |
| `privacy_officer` governance surface                                                                        | Prototype                                                                                                                                                                                                                                            | `services/control-plane`, `apps/console`            |
| Load, chaos, DR, NFR                                                                                        | Prototype, one small VM, honest Met/Not-met/Not-measured table                                                                                                                                                                                       | `perf/`, `chaos/`, `infra/dr/`, `docs/nfr.md`       |
| STRIDE threat models + red team                                                                             | Built as a regression net (scripted model: platform containment, not model robustness)                                                                                                                                                               | `docs/security/`, `evals/redteam/`                  |
| **Phase 10 — Helm charts**                                                                                  | **Built** (chart-level validation: real `helm lint`/`template`+`kubeconform`, real `docker build`+`run`+`/health` for every image; no live-cluster install at full 14-chart scale)                                                                   | `infra/helm/`                                       |
| **Phase 10 — Terraform (AWS/GCP/Azure)**                                                                    | **Built** (`validate`/`fmt` clean for all; `plan` verified with dummy credentials for AWS and GCP; Azure's provider dials out for a live token even to plan and is genuinely unverifiable without a real Azure AD app this project will not request) | `infra/terraform/`                                  |
| **Phase 10 — Local k3d cluster**                                                                            | **Deployed** (narrowly: risk-kernel + Python runtime + Postgres, real images, real cluster, real gRPC call, real hash-chained audit row verified, then torn down)                                                                                    | `docs/runbooks/local-cluster.md`                    |
| **Phase 10 — Release process**                                                                              | Designed (runbook written; never exercised — publishing images/charts publicly is a hard stop)                                                                                                                                                       | `docs/runbooks/release.md`                          |

## Test and coverage results (latest full sweep, this session)

All 29 of this project's `make`/`pnpm`/`uv` gate targets ran clean on the
final merged Phase 10 tree, one target at a time (never in parallel, to avoid
the CPU/IO contention this sandbox has shown under load):

- `pnpm build`, `pnpm lint`, `pnpm typecheck`: clean, 46 TS tasks
- `pnpm exec turbo run cov --force --concurrency=2`: **97.47% overall line
  coverage**, 46/46 tasks, required-85%-floor gate passed (core packages
  individually meet the 95% floor per CLAUDE.md; `@axis/ui` has no coverage
  output by design, a known Turborepo config gap, not a test gap)
- `uv run pytest runtime sdk/python -q`: **3005 passed**, 97.48% coverage
  (122 s)
- `uv run ruff check . && uv run ruff format --check .`: clean
- `uv run mypy runtime/src sdk/python/src`: clean, strict mode
- `make policy-test contracts-lint compliance-check threatmodel-check
redteam-lint`: clean
- `make e2e-core` through `make e2e-phase9`, `e2e-compliance`,
  `e2e-governance`, `console-e2e`, `docs-build`, `evals`: clean (combined:
  several hundred scenario-level assertions across all 9 phase exits plus
  compliance/governance/console/docs/evals suites — see each phase's
  `CHANGELOG.md` entry for exact counts)
- `make redteam`: 254 counted attack cases, containment 1.0000, 0 unsafe,
  all 6 release gates allow; `make redteam-selfcheck`: all 10 mutants
  detected
- `make chaos`: 23 tests (18 fault-injection + 5 proxy-ordering), one
  observed timing flake on retry (the slow-gate-timeout test, inherently
  timing-sensitive under this sandbox's shared CPU — passed clean on
  immediate retry, not a regression)
- `make dr-drill`: fresh drill this session — kill -9 + delete, logical and
  physical restore, both tamper negatives detected, RTO ~1.3 s, result
  committed to `infra/dr/results/`

CI note (unchanged from Phase 9): every one of these targets has a GitHub
Actions job defined in `.github/workflows/ci.yml`, but **none has executed
remotely** in this project's history — every green result above (and in
every phase before it) is from this session's own local execution.

## NFR results (full detail: `docs/nfr.md`)

Measured on one shared 4-vCPU / 15.7 GiB VM — **no extrapolation to cluster
or production scale is made anywhere in this document**:

- **Met**: policy decision p99 0.071 ms (in-process); gate overhead p99
  11.9 ms at 50 calls/s/tenant (not met at 100/s+ on this machine); control
  plane API p99 14-172 ms up to 300 RPS tested; kill-switch propagation
  p50 3.9 ms / max 15 ms (single instance); RPO 0-2 events lost over 5
  drills; RTO 1.3-1.5 s for this drill's data size; run start ack p99
  53 ms; one gated model call p99 108 ms (scripted model); audit append
  420-1785 events/s depending on caller/chain fan-out; chain verify 1.8 s
  for 100k events; SSE fan-out 500 subscribers p99 2.7 s, 0 failures
- **Not measured**: 1k RPS/region (needs a separate load host and a sized
  region); 10k concurrent agent processes/region (no sizing produced);
  eval throughput (scripted model makes a number meaningless);
  cross-instance kill-switch propagation (single instance only)
- **Designed, not deployed**: 99.9% multi-AZ availability (no HA
  deployment exists anywhere in this project, including the Phase 10
  local-cluster run, which was a single k3d node)

## What Phase 10 actually added over Phase 9

Phase 10 is the first phase to touch infrastructure outside the per-process
dev harness every earlier phase ran against. Three real, independently
verified pieces, plus an independent Phase 9 review folded in:

1. **An independent Phase 9 review** closed real findings in the Risk
   Kernel's tool-side-effect classifier (a `ref`-vs-`name` alias bypass,
   glued/unicode/digit-obfuscated tool names, and nested argument keys the
   scanner never looked at — ADR 0114), a legal-hold time-of-check/time-of-
   use gap in data-governance erase and retention (ADR 0115), an
   audit-before-purge ordering fix, and a compliance-matrix symlink-evidence
   escape. Every finding shipped with a reverting test.
2. **Helm charts and production Dockerfiles** for every containerizable
   AXIS process, validated at the chart level (`helm lint`/`template` +
   `kubeconform -strict` across 14 charts x 6 values overlays) and at the
   image level (every image actually built and run with a passing
   `/health` check) — this surfaced and fixed real bugs (a NetworkPolicy
   default that was open to every namespace instead of just the local one,
   three separate image-build defects) that neither validation tier alone
   would have caught.
3. **Terraform modules** for AWS, GCP, and Azure, engineered specifically
   to minimize live-cloud-API dependency so `validate`/`fmt` — and, for two
   of the three clouds, even `plan` — could be genuinely verified with no
   real cloud account, honoring the standing hard stop against ever
   running `apply` or touching a real account.
4. **A real local Kubernetes cluster.** Not a template-rendering exercise:
   a real k3d cluster was created in this sandbox, real container images
   built from this repo's own source were imported into it, `helm
install`ed, and a real gRPC `Evaluate` request was sent from a real
   runtime pod to a real Risk Kernel pod living in that cluster. The
   resulting ALLOW and default-DENY decisions were independently confirmed
   by querying the real Postgres pod's `audit_events` table directly and
   checking that the DENY row's `prev_hash` equals the ALLOW row's `hash`
   — proof of a live, append-only hash chain, not a mocked one. The
   cluster was torn down afterward; it does not persist. This is narrow
   (3 of 14 services, one node, no HA) but it is real, and it is the first
   thing in this project's history to earn the status "Deployed" rather
   than "Built."

## Honest gaps carried forward (see `docs/NEEDS.md` for the full, numbered list)

The single largest gap across the whole project, restated plainly: **every
external boundary in this system — identity provider, KMS, DNS, every model
provider, Stripe, telephony, cloud provider APIs, and (as of Phase 10) a real
Kubernetes cluster at full production scale — has been exercised only against
this project's own fakes, or (for the Phase 10 local-cluster slice) against a
single throwaway node.** Nothing has ever talked to a real external service.
Specific standing gaps, not exhaustive (numbers refer to `docs/NEEDS.md`):

- No CI job in `.github/workflows/ci.yml` has ever executed remotely, for
  any phase (#421 and throughout).
- Single-instance, in-memory state in several services (Risk Kernel,
  TKI/NEXUS, approvals) — no cross-instance coordination exists.
- The code sandbox is process-level isolation (real namespaces on one
  kernel), not a security boundary (no seccomp/gVisor/Firecracker, #89-95).
- Azure Terraform `plan` cannot be verified without a real Azure AD app
  registration (#500); no cloud's Terraform modules have ever planned
  against an _existing_ (non-empty) environment (#505); no remote
  Terraform state backend configured anywhere (#501).
- 11 of 14 Helm charts have never been installed against a live cluster
  (only risk-kernel, runtime, and Postgres were); `control-plane`'s image
  is missing a policy-pack file and crash-loops on a real cluster (#514);
  the other 11 service images share a `runAsNonRoot`-vs-numeric-`USER` gap
  found and fixed only for the 3 deployed (#516).
- 99.9% availability, 1k RPS/region, and 10k-agent/region targets are
  Designed but not measured at any scale beyond this one shared VM.

## Deploy commands (as they exist today)

```bash
# Local dev stack (compose) — verified running in Phase 10
make dev            # all 9 containers healthy
make dev-health      # health check
make dev-down        # tear down

# Local Kubernetes — no single command yet; see the runbook for the full,
# verified, reproducible step-by-step (image builds, k3d-tools-local build,
# cluster create, helm install, gRPC smoke check, teardown)
docs/runbooks/local-cluster.md
make k3s-up          # currently points at the runbook; exits 1

# Cloud infrastructure planning (never apply; real cloud credentials
# required for a plan against a real, non-empty account)
make tf-plan CLOUD=aws
make tf-plan CLOUD=gcp
make tf-plan CLOUD=azure

# Full verification sweep (what this report's numbers come from)
pnpm build && pnpm lint && pnpm typecheck
pnpm exec turbo run cov --force --concurrency=2
make policy-test contracts-lint compliance-check threatmodel-check redteam-lint
make e2e-core e2e-phase3 e2e-phase4 e2e-phase5 e2e-phase6 e2e-phase7 e2e-phase8 e2e-phase9
make e2e-compliance e2e-governance console-e2e docs-build evals
make redteam redteam-selfcheck chaos dr-drill
uv run ruff check . && uv run ruff format --check .
uv run mypy runtime/src sdk/python/src
uv run pytest runtime sdk/python -q
```

## Release

See `docs/runbooks/release.md` for the full versioning scheme and release
gate. No release has been tagged or published; publishing images or charts
publicly is a standing hard stop per `CLAUDE.md` and has never been crossed.
