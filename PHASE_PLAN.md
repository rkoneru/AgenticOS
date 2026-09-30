# AXIS — Phase Plan

Autonomous execution. Each phase starts in plan mode (`docs/plans/phase-N.md`) and ends with a **phase-exit routine**: full tests, coverage gates, lint/typecheck, security scans, evals, an independent review subagent against the exit criteria, `CLAUDE.md` status table updated, `CHANGELOG.md` entry. Do not start the next phase until exit criteria are met — but do not wait for human approval either.

Hard stops (spend, real cloud, public publishing, missing credentials) are the only pauses. See `CLAUDE.md`.

---

## Phase 0 — Inventory and foundations
**Goal:** Understand what exists; stand up the monorepo skeleton.
- Read the reference kernel and five docs; write `docs/INVENTORY.md` with honest status.
- Merge the `CLAUDE.md` seed; create `AGENTS.md`, `SKILLS.md`, `ROUTINES.md`, `docs/NEEDS.md`, `docs/adr/0001-record-architecture-decisions.md`.
- pnpm + Turborepo + uv workspace; lint/format/typecheck configs; pre-commit hooks.
- CI pipeline (GitHub Actions): lint, typecheck, test, coverage gates, SAST, dependency and container scanning, SBOM.
- `make dev` brings up Postgres+pgvector, Redis, ClickHouse, Temporal, OPA, OTel collector, Jaeger/Grafana via compose.

**Exit:** CI green on an empty-but-wired repo; `make dev` healthy; inventory and ADR-0001 written.

## Phase 1 — Contracts (freeze point)
**Goal:** Lock the interfaces everything else builds against.
- **ABL v1**: JSON Schema, spec doc, examples, versioning rules; risk-classification field (EU AI Act).
- **Policy DSL v1**: YAML schema + decision model (`ALLOW / DENY / REQUIRE_APPROVAL / ALLOW_WITH_REDACTION`).
- **Process model**: states, signals, IPC message envelope, PID scheme.
- **Audit event schema** (hash-chained).
- `proto/` for runtime ↔ control plane; OpenAPI 3.1 for public `/v1`.
- Postgres schema with RLS for all tenant tables; migration tooling.
- ADRs: API framework, OPA mode (sidecar vs Wasm), sandbox tech (gVisor vs Firecracker), tenancy tiers.

**Exit:** Contracts versioned and frozen; contract tests scaffolded; RLS isolation tests passing.

## Phase 2 — Governed kernel (the core loop)
**Goal:** One agent, end to end, through the gate.
- ABL compiler (YAML → runtime manifest) with linter and error messages. **95% coverage.**
- Policy compiler (YAML DSL → Rego) with golden tests and `axis policy test`. **95%.**
- Risk Kernel service: generalized gate types (kill-switch, staleness, size/amount caps, target caps, drawdown/budget, rate-of-fire), fail-closed defaults, kill-switch < 1 s. **95%.**
- Python runtime: process lifecycle on Temporal workflows, event-sourced state, replay.
- ModelGateway with Anthropic, OpenAI, Google, Azure OpenAI, Bedrock, OpenAI-compatible adapters; BYO keys via KMS-backed secrets.
- Audit service: append-only, hash-chained, WORM export.
- **Bypass test:** fails the build if any action path skips the Risk Kernel.

**Exit:** An ABL agent runs, calls a tool, is allowed/denied correctly, and its run replays from the log.

## Phase 3 — Orchestration and routing
- **TKI**: scheduler, supervisor trees, IPC, token/cost budget ledger (tenant/agent/run), hard and soft caps. **95%.**
- **NEXUS**: cache → rules → MPM → RAG → LLM pipeline with per-stage telemetry and cost attribution.
- **MPM stub**: interface, registry, mock models, routing slot, benchmark harness.
- Human approval queue: `REQUIRE_APPROVAL` flow, SLAs, escalation, notifications (Slack/Teams/email adapters with fakes).

**Exit:** Multi-agent run with budgets enforced, NEXUS stage metrics visible in traces, approvals working end to end.

## Phase 4 — Memory, tools, and execution surfaces
- Memory service: run/session/long-term/vector memory, KB ingestion, chunking, ACL-aware retrieval.
- MCP client (agents consume external servers) and MCP server (expose AXIS agents/tools) — all calls gated.
- Sandboxed code tools (isolated, no-network default, limits, artifact capture).
- Browser workers (Playwright, isolated pods, domain allowlists, capture to audit).

**Exit:** Agents use memory, MCP, code, and browser tools; every call appears in audit with a policy decision.

## Phase 5 — Channels and voice
- Channel abstraction; adapters: web widget, Slack, Teams, email, SMS, WhatsApp.
- Voice: streaming STT → agent → TTS, barge-in, provider adapters, SIP/WebRTC gateway.
- Unified end-user conversation state across channels.

**Exit:** The same agent serves chat and voice across at least three channels, with transcripts in audit.

## Phase 6 — SaaS platform
- WorkOS: SSO (SAML/OIDC), SCIM, admin portal; RBAC + ABAC via OPA.
- Tenancy tiers: shared RLS, dedicated DB + node pool (regulated), single-tenant VPC deploy.
- Usage-based billing: meters (tokens, runtime seconds, tool executions, voice minutes, storage, marketplace installs), ClickHouse usage ledger, Stripe metered billing (test mode only), invoice reconciliation. **95% on ledger.**
- Tenant admin: members, roles, API keys, BYO model keys, policy packs, budgets, retention, region.

**Exit:** New tenant can sign up via SSO, configure keys and policies, run agents, and see accurate metered usage.

## Phase 7 — Interfaces and ecosystem
- Web console: blueprints (editor with ABL validation), runs (live + replay), approvals, policies, evals, audit explorer, usage, admin. AGIL explanations beside every run and denial.
- CLI `axis`: full parity for core workflows.
- REST `/v1` + gRPC; TS and Python SDKs generated + ergonomic layer; docs site.
- Agent registry: semver, signing, provenance.
- Public marketplace: publisher verification, security review workflow, install, publisher usage metering.

**Exit:** Every core workflow is doable from console, CLI, and both SDKs; e2e suites green.

## Phase 8 — Eval Hub integration
- Integrate Eval Hub: datasets, graders (deterministic, model-graded, human), regression suites.
- CI gating on eval thresholds per blueprint; online eval sampling of production runs.
- Eval results linked to blueprint versions in registry and console.

**Exit:** Blueprint releases are blocked when evals regress; eval history visible per version.

## Phase 9 — Compliance, security, and hardening
- `docs/compliance/` control matrix: SOC 2, GDPR, HIPAA, EU AI Act, ISO 42001 → code, config, evidence. Label "designed for / evidence-ready", never "certified".
- DSAR export/delete, retention enforcement, PHI mode with redaction-before-persistence, residency pinning.
- EU AI Act technical documentation generator; ISO 42001 AI inventory and impact assessment records.
- STRIDE threat models per service, including prompt injection and tool misuse; red-team eval suite.
- Load tests (k6) against NFR targets; chaos tests; DR plan with a tested restore.

**Exit:** NFR targets met or gaps documented; control matrix complete; red-team suite passing thresholds.

## Phase 10 — Deployment and release
- Helm charts for every service; values for `local`, `k3s-homelab` (reduced footprint), `aws`, `gcp`, `azure`, `dedicated`.
- Terraform modules for AWS, GCP, Azure (networking, K8s, Postgres, Redis, ClickHouse, object storage, KMS). **`terraform plan` only — apply is a hard stop.**
- Deploy to local k3s and run the full e2e suite against it.
- Release process, versioning, and runbooks.
- `docs/FINAL_REPORT.md`: status per component with evidence, test/coverage/eval results, NFR results, open items, deploy commands.

**Exit:** Full stack running on k3s with e2e green; cloud plans clean; final report written.

---

## Coverage and quality gates (all phases)
- 95% line and branch: ABL compiler, policy compiler, Risk Kernel, TKI scheduler/budgets, audit log, billing ledger, tenancy/RLS.
- 85% elsewhere. Evals gated per blueprint. Bypass test and cross-tenant isolation tests must always pass.
