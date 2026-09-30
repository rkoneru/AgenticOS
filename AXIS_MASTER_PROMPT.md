# AXIS — Master Build Prompt for Claude Code

> Paste this whole file as your first message in Claude Code, from the root of the AXIS repo.
> Keep `CLAUDE.md` (seed) and `PHASE_PLAN.md` from this pack in the repo root beside it.

---

## 0. Your role and mandate

You are the principal engineer and architect for **AXIS**, an enterprise **Agentic Operating System delivered as SaaS**. You will build it **autonomously, end to end**, to a **production-ready** bar. You own architecture, implementation, tests, infrastructure-as-code, and documentation.

You work from an existing foundation. Before writing new code, read and absorb:

- The existing five-file Python reference kernel in this repo
- `CLAUDE.md`, `ARCHITECTURE.md`, `DESIGN-DECISIONS.md`, `ABL-SPEC.md`, `ROADMAP.md`

Treat those as the canonical intent. Where this prompt extends or conflicts with them, this prompt wins for *scope*, and the existing docs win for *core concepts* (process model, fail-closed gate, ABL semantics). Record every reconciliation in an ADR.

**Independence rule:** AXIS is independent, closed-source work. Do not use, reference, or imitate any employer's code, product names, customer data, or internal patterns.

---

## 1. Product definition

**One line:** AXIS is a governed runtime where AI agents run as OS-style processes — declared in ABL, routed through NEXUS, orchestrated by TKI, gated by the Risk Kernel, explained by AGIL, and measured by Eval Hub — offered to enterprises as a multi-tenant SaaS.

**Customer:** Enterprise (regulated industries included — healthcare, financial services, public sector).

**Core promise:** No agent action executes without passing a fail-closed policy gate, and every action is attributable, replayable, and explainable.

### 1.1 First-class modules

| Module | Role in AXIS | v1 expectation |
|---|---|---|
| **ABL** | Declarative YAML agent blueprints — the "executable format" of AXIS | Full spec, JSON Schema, validator, linter, compiler to runtime manifest, versioning |
| **Risk Kernel** | Fail-closed pre-action gate upstream of *all* execution, including MCP and tool calls | Generalize the six trading gates (kill-switch, staleness, size, venue cap, drawdown, rate-of-fire) into tenant-configurable gate types; default-deny |
| **TKI** | Multi-agent orchestration kernel with token budgets | Scheduler, budget ledger per tenant/agent/run, supervisor trees, IPC |
| **NEXUS routing** | Hybrid router: cache → rules → MPM → RAG → selective LLM | Pluggable pipeline with per-stage telemetry and cost attribution |
| **MPM** | Micro Precision Models (100M–500M params) invoked before large LLMs | **Stubbed**: interface, registry, routing slot, mock models; real models later |
| **AGIL** | Human-facing explanation/generation layer | Explanations for runs, decisions, and denials. **AGIL never governs and never sits on the decision path** — enforce this architecturally (it only reads from the audit log) |
| **Eval Hub** | LLM and agent evaluation | Datasets, graders, regression suites, CI gating, online eval sampling |

### 1.2 Interfaces (all in scope)

- **Web console** — Next.js, React, Tailwind, shadcn/ui. Dense, dark-first ops-console aesthetic.
- **CLI** — `axis` (TypeScript), covering auth, blueprint lint/deploy, run, logs, approvals, evals.
- **REST API** — OpenAPI 3.1, versioned (`/v1`), generated from source of truth.
- **gRPC** — for runtime ↔ control plane and high-throughput clients; protobuf in `/proto`.
- **SDKs** — TypeScript and Python, generated from OpenAPI + hand-written ergonomic layers.
- **MCP** — AXIS as an **MCP server** (expose agents/tools to external clients) and **MCP client** (agents consume external MCP servers). Every MCP call passes the Risk Kernel.
- **Agent registry** — private, per-tenant registry of blueprints, tools, skills with semver and signing.
- **Public marketplace** — cross-tenant listing, publisher verification, security review workflow, install into tenant. Usage metering hooks for publishers.

### 1.3 Runtime capabilities (all in scope)

- **Agents as OS processes** — lifecycle: `spawn → ready → running → waiting → suspended → terminated`; PIDs, parent/child trees, signals (pause, resume, kill), resource quotas, IPC channels.
- **Durable, event-sourced workflows on Temporal** — every run is a Temporal workflow; agent state is reconstructed from an append-only event log; full replay.
- **Human-in-the-loop approval queue** — policy can return `REQUIRE_APPROVAL`; approvals via console, CLI, API, and Slack/Teams/email notifications; SLA timers; escalation.
- **Memory and RAG service** — short-term (run), working (session), long-term (agent/tenant), vector (pgvector), per-tenant knowledge bases with ingestion, chunking, ACL-aware retrieval.
- **Sandboxed code tools** — isolated execution (gVisor or Firecracker microVMs), no network by default, CPU/mem/time limits, artifact capture.
- **Browser tools** — headless browser workers (Playwright) in isolated pods, domain allowlists, screenshot/DOM capture into the audit trail.
- **Voice channel** — real-time voice agents (streaming STT → agent → TTS), barge-in, pluggable providers, telephony via SIP/WebRTC adapter.
- **Omnichannel** — channel adapters (web chat widget, Slack, Teams, email, SMS, WhatsApp, voice) behind one channel abstraction; conversation state unified per end-user.

### 1.4 Models

- **Multi-provider, provider-neutral.** A single `ModelGateway` abstraction with adapters (Anthropic, OpenAI, Google, Azure OpenAI, AWS Bedrock, and any OpenAI-compatible endpoint).
- **Bring your own keys** per tenant, stored in a KMS-backed secret store; platform keys as fallback only when the tenant allows it.
- Streaming, tool-calling, structured output, prompt caching where the provider supports it, retries with jitter, circuit breakers, per-provider cost tables.

---

## 2. Governance, safety, and compliance

### 2.1 Policy
- **Policy authoring:** an AXIS YAML policy DSL (extends the Risk Kernel YAML), **compiled to OPA/Rego**. Ship the compiler, a schema, a test harness (`axis policy test`), and golden tests.
- **Decision outcomes:** `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ALLOW_WITH_REDACTION`. Default is `DENY` on any error, timeout, or missing policy (**fail-closed**).
- **Enforcement points:** before every tool call, MCP call, model call (for data-egress rules), memory write, external message send, and code/browser execution.
- **Kill-switches:** global, tenant, agent, and tool level, effective in under 1 second.

### 2.2 Audit
- Append-only, hash-chained, tamper-evident audit log (per-tenant), exported to WORM object storage.
- Every event carries: tenant, actor (human/agent PID), blueprint version, policy version, decision, inputs hash, outputs hash, trace ID.
- Full run replay from the event log in the console.

### 2.3 Compliance design targets
Design and document controls for **SOC 2 (Type II-ready), GDPR, HIPAA, EU AI Act, ISO/IEC 42001**. Concretely:
- Data residency per tenant (region-pinned deployments), DSAR export/delete tooling, retention policies.
- PHI handling mode: encryption with tenant-scoped keys, BAA-ready architecture, PHI-aware logging (redaction before persistence).
- EU AI Act: risk classification field on every blueprint, transparency notices for end users, human oversight hooks, technical documentation generator.
- ISO 42001: AI system inventory, impact assessment records, model/prompt change management.
- Produce `docs/compliance/` with a control matrix mapping each control to code, config, and evidence source. **Do not claim certification** — label everything "designed for" / "evidence-ready".

### 2.4 Security baseline
- WorkOS for SSO (SAML/OIDC), SCIM directory sync, and admin portal. RBAC + ABAC (roles plus attribute conditions evaluated in OPA).
- Service-to-service mTLS, short-lived credentials, least-privilege IAM, secrets never in env files committed to git.
- Threat model (STRIDE) per service in `docs/security/`. Include prompt-injection and tool-misuse threats specific to agents.
- Dependency scanning, SAST, container scanning, SBOM generation in CI.

---

## 3. SaaS platform

- **Tenancy:** tiered isolation.
  - Standard: shared Postgres with row-level security, tenant ID on every row, enforced at the DB, not just the app.
  - Regulated (HIPAA/residency): dedicated database and dedicated runtime node pool per tenant.
  - Enterprise dedicated: single-tenant deployment into a customer VPC/cloud account via the same Helm/Terraform.
- **Billing: usage-based only.** Meter tokens (by provider/model), agent-runtime seconds, tool executions, voice minutes, storage, and marketplace installs. Stripe metered billing, usage ledger in ClickHouse, invoices reconcile to the ledger, hard and soft budget caps enforced by TKI.
- **Tenant admin:** org settings, members, roles, API keys, BYO model keys, policy packs, budgets, data retention, region.

---

## 4. Technology stack (fixed)

| Layer | Choice |
|---|---|
| Monorepo | pnpm + Turborepo; `uv` for Python packages |
| Control plane | TypeScript (Node 22 LTS), Fastify or NestJS (pick one, write the ADR), tRPC internally only if justified |
| Agent runtime | Python 3.12+, asyncio, Temporal Python SDK |
| Workflow engine | Temporal (self-hosted on K8s; Temporal Cloud supported by config) |
| Console | Next.js (App Router), React, Tailwind, shadcn/ui |
| Primary DB | PostgreSQL 16 + pgvector |
| Cache / queues | Redis |
| Analytics / traces | ClickHouse |
| Telemetry | OpenTelemetry end to end (traces, metrics, logs); LLM spans follow the OTel GenAI semantic conventions |
| Policy | OPA (sidecar or embedded Wasm — ADR) |
| Auth | WorkOS |
| Payments | Stripe |
| IaC | Terraform (AWS, GCP, Azure modules) + Helm charts |
| Local dev | docker-compose (`make dev` brings up everything) |
| Edge target | Home-lab K8s profile (k3s) with a reduced footprint values file |

Suggested repo layout (adjust with an ADR if needed):

```
axis/
  apps/            console, api-gateway, cli, docs-site
  services/        control-plane, policy, registry, marketplace, billing,
                   memory, channels, voice, approvals, audit
  runtime/         python agent runtime, tool sandboxes, browser workers
  packages/        abl (spec+compiler), sdk-ts, shared types, ui kit
  sdk/python/      python SDK
  proto/           gRPC contracts
  policies/        default policy packs + tests
  evals/           Eval Hub suites
  infra/           terraform/{aws,gcp,azure}, helm/, compose/, k3s/
  docs/            architecture, adr/, compliance/, security/, runbooks/
```

---

## 5. How you work (autonomous mode)

You run **end to end without waiting for approval between phases**. To stay safe and correct while autonomous:

1. **Plan before building.** Use plan mode at the start of each phase in `PHASE_PLAN.md`. Write the plan to `docs/plans/phase-N.md`, then execute it.
2. **Decide and record.** For every significant choice write an ADR in `docs/adr/NNNN-title.md` (context, options, decision, consequences). Never block on a question you can decide; pick the most defensible option and record why.
3. **Keep the docs live.** Maintain `CLAUDE.md`, `AGENTS.md`, `SKILLS.md`, `ROUTINES.md`, and `ARCHITECTURE.md` as you go. Every component gets an honest status label: `Concept / Designed / Prototype / Built / Deployed`. Never label something higher than the evidence supports.
4. **Parallelize safely.** After the Phase 1 contracts (proto, OpenAPI, ABL schema, DB schema) are frozen, use subagents in separate git worktrees for independent services. Each subagent gets: the contract files, its service's scope, and the Definition of Done. Merge only when its CI is green.
5. **Self-verify at every phase exit.** Run the full test suite, lint, type-check, security scans, and the phase's exit criteria. Have a separate review subagent — one that did not write the code — audit the phase against its exit criteria and this prompt. Fix everything it finds before moving on.
6. **Commit discipline.** Small conventional commits, one logical change each. Update `CHANGELOG.md` per phase.
7. **Hard stops (the only times you pause for me):**
   - Anything that spends real money or touches real cloud accounts (`terraform apply` against a non-local target, creating Stripe live objects, purchasing domains).
   - Anything irreversible outside the repo (publishing packages, pushing to public registries, DNS changes).
   - Needing credentials you don't have. Use mocks/fakes and keep going; list what you need in `docs/NEEDS.md`.
   Everything else — local builds, tests, local compose/k3s deploys, `terraform plan` — you do yourself.
8. **Never fake it.** No placeholder implementations reported as done, no skipped tests to go green, no hard-coded eval results. If something can't be built properly yet, mark it `Prototype` or `Designed`, explain the gap in `docs/NEEDS.md`, and continue.

---

## 6. Definition of Done (applies to every service)

- [ ] Implements its contract (OpenAPI/proto) with no drift (contract tests pass)
- [ ] **95% line and branch coverage** on core packages (ABL compiler, policy compiler, Risk Kernel, TKI scheduler/budgets, audit log, billing ledger, tenancy/RLS); ≥85% elsewhere. Coverage enforced in CI.
- [ ] Unit, integration (Testcontainers), and e2e (Playwright for console, CLI e2e) tests
- [ ] Agent behavior covered by Eval Hub suites with pass thresholds gated in CI
- [ ] Every external action path proven to hit the Risk Kernel (a test that fails if a new tool path bypasses it)
- [ ] Multi-tenant isolation tests: cross-tenant read/write attempts must fail at the DB layer
- [ ] OTel traces, metrics, and structured logs; dashboards defined as code
- [ ] Helm chart, health/readiness probes, resource limits, HPA
- [ ] Runbook in `docs/runbooks/`, threat model entry, status label updated
- [ ] No secrets in code; no TODOs without a linked entry in `docs/NEEDS.md`

---

## 7. Non-functional targets

- Policy decision p99 < 10 ms (in-cluster); gate adds < 25 ms p99 to a tool call
- Control-plane API p99 < 200 ms at 1k RPS per region (load test with k6)
- Runtime: 10k concurrent agent processes per region on reference cluster sizing (document the sizing)
- Kill-switch propagation < 1 s
- RPO ≤ 5 min, RTO ≤ 1 h; documented DR plan with restore test
- Availability design target 99.9% (multi-AZ)

---

## 8. Start now

1. Read the existing kernel and five docs. Summarize what exists and its honest status in `docs/INVENTORY.md`.
2. Replace the repo's `CLAUDE.md` with the seed from this pack, merged with anything valuable in the existing one.
3. Open `PHASE_PLAN.md` and begin Phase 0.
4. Work through every phase to completion. At the end, produce `docs/FINAL_REPORT.md`: what's built, status per component with evidence links, test/coverage/eval results, open items from `docs/NEEDS.md`, and the exact commands to deploy locally, to k3s, and to each cloud.
