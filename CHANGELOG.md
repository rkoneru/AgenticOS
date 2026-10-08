# Changelog

## Phase 9 / A — 2026-10-08 — Compliance matrix, technical documentation, ISO 42001 records

- `docs/compliance/`: control matrices (YAML source, generated Markdown) for SOC 2, GDPR, HIPAA, the EU AI Act and ISO/IEC 42001: 118 rows, each
  with mechanism, code, config, evidence and an honest status. Labelled "designed for / evidence-ready"; never certified or compliant.
- `services/compliance` (`@axis/compliance`): `make compliance-check` (fails on cited paths, tests or make targets that do not exist, `Built`
  without executable evidence, forbidden wording, missing required rows, stale rendered Markdown); a deterministic, sealed EU AI Act Annex IV
  technical documentation generator that lists every missing source as a gap; ISO/IEC 42001 AI system inventory and AI impact assessments
  (versioned, independent reviewer enforced in the service and by a database constraint, overdue detection).
- Migration 0016 (`compliance_docs`, forced RLS, append-only collections); ADRs 0070-0074; OpenAPI 1.5.0 (14 operations, FREEZE and SDKs
  regenerated); `api.compliance.read|write|review` in the control-plane pack with 21 golden cases; gateway routes and adapters; ergonomic
  wrappers in both SDKs; `axis compliance ...`; read-only console pages (axe in both themes, XSS).
- Spec `docs/spec/compliance.md`, runbook, threat model; NEEDS #346-361 (the parent renumbers).

## Phase 8 - exit: evals gate releases, proven end to end (`make e2e-phase8`, `make console-e2e`, `make evals`)

**One additive contract change: OpenAPI 1.4.0** (ADR 0059: `listRegistryEvalAttestations`, re-verified on every read; FREEZE regenerated, SDKs and
CLI `axis registry attestations`). No migration. Status: Prototype (scripted models; NEEDS #325-#334; ADR 0058; `docs/runbooks/evals-e2e.md`).

- `e2e/test_phase8_evals.py` (22 tests) on the Phase 7 stack plus the Eval Hub and a REAL `eval_runner` process per tenant (kernel gates every model and tool
  call, the judge included; the only fake is the scripted model): v1 (deterministic + model + human graders) runs, a reviewer grades, the hub
  recomputes, the gate allows, the registry releases, the signed attestation is on the version; v2 regresses (passes its own bar, drops 0.35 vs the
  baseline) and is BLOCKED (`regression`) from TS SDK, Python SDK and CLI (exit 4), registry release and marketplace submit refuse with
  `evals_gate_failed`; fail-closed cases (no run, other content, revoked and unregistered runners, tampered score, replayed result, threshold, unknown
  suite, newest run decides); human review (publisher/starter excluded, double grade + adjudication); online sampling of real production runs
  (selection recomputed from run ids, PHI redacted before the judge and the hub, history only, release state untouched); judge injection (a gullible
  scripted judge proves the defences carry the result); eval-mode safety (payout/wire/code never run, same decisions as production); cross-tenant from
  every client; a tenant without the judge rule gets `ungraded`, not a pass. 13 wiring mutants (`e2e/mutation_phase8.py`).
- Console: runs (live status), run detail (per-grader chart, per-case drill-down, kernel decisions, audit trace link), datasets, suites, baselines with
  comparison charts (plain SVG, fixed 0..1 axis, table view), review queue, online history, and a release-gate panel (verdict, reasons, version history,
  attestations) on the blueprint version and registry pages; 8 new mock flows + axe on 8 pages x 2 themes; 10 real-stack Playwright tests with a real runner.
- Gap closures: network manifest source (hub route, runner-scoped), read-only redacted run feed + `eval_runner.py --online`, judge policy pack
  (`policies/eval-judge`), canonical JSON parity (shared vectors), online human review tasks, registry/marketplace ask the gate whenever a hub is wired,
  the gateway gate route always asks the stored ABL's declared suites.
- Defects found only by this wiring and fixed: an eval payout opened a real approval request (non-UUID run id) and broke `listApprovals` (kernel `eval_mode`
  marker); a gate call without `suites` answered ALLOWED (gateway now adds the declared ones); the staff-side registry in the harness was not wired to the hub.
- `make evals` is real: hub suite (95% on the safety modules) + runner/grader/sampler suite (>= 95% on `axis_runtime.evals`) + judge pack golden cases. No live model.
- Honest gaps: scripted model only (#307), a registered runner can forge consistent results (#326), release step is harness ops (#331), `main.ts` still has no
  attestation sink (#301), console is read-mostly and polls (#330).

## Phase 8 - Eval Hub (component H, `services/eval-hub`)

**One additive contract change: OpenAPI 1.3.0** (ADR 0057; FREEZE regenerated; 22 operations). Migration 0013. Status: Prototype
(ADR 0056; NEEDS #293-#305; `docs/spec/eval-hub.md`).

- `@axis/eval-hub`: immutable versioned datasets (content hash, PHI redaction before persist), suites, runner-aligned score recompute (13 pinned vectors), append-only runs, baselines, regression comparison with a deterministic paired sign-flip test, human review queue (SLA, double grading, adjudication, reviewer != publisher/starter), fail-closed gate bound to content hash and registered runners, signed DSSE attestations on registry versions, online sampling, Postgres stores with forced RLS, dev HTTP server.
- Registry and marketplace refuse with 409 `evals_gate_failed` (+ reasons) through an injected gate port (default deny).
- Gateway: `startEvalRun` real, 22 evals operations; control-plane `api.evals.*` actions; both SDK ergonomic layers; `axis evals ...` CLI.
- Honest gaps: ephemeral attestation key, dev tokens, runner-side grading trusted for raw grades (NEEDS #293-#305).

## Phase 7 - Interfaces and ecosystem exit (component E, `make e2e-phase7`, `make console-e2e`)

**One additive contract change: OpenAPI 1.2.0** (ADR 0053; FREEZE regenerated, 17 operations: `GET /v1/me`, approval by id, policy activation, registry, marketplace). Status: Prototype on the real stack
(dev composition; ADR 0054; NEEDS #272-#283).

- API gateway: standalone process (`main.ts`, env config, token files, refuses `NODE_ENV=production`), registry/marketplace/identity/approval-by-id/activation adapters, new `api.*` actions in the control-plane pack with golden cases.
- SDKs + CLI regenerated; `me`, `registry.*`, `marketplace.*` (consent-bound `installWithConsent`), `policies.activate`; CLI `whoami` (tenant, role), `policies activate`, `registry keygen|sign|publish|resolve|...`, `marketplace search|preview|install|...`, `run explain`, `audit explain`.
- Console wired to the real API: BFF routes `/v1` to the gateway (cookie to bearer) and `/admin`, `/auth` to the control plane; SSO route handler; registry, kill-switch pages; consent-based marketplace install; SSE reconnect (`followRun`); runtime event vocabulary in replay.
- Real-stack harness (`e2e/interfaces_stack.py`): Postgres, real Risk Kernel, control plane, billing, marketplace staff side, fake IdP, scripted-model run service, standalone gateway.
- `make e2e-phase7`: 36 tests = (identity/policy/blueprint, signed registry publish + verified resolve, marketplace consent install by a second tenant, run + SSE + approve + replay, deny, audit verify + tamper on a corrupted copy + AGIL derived from audit rows, usage == ledger, kill-switch, cross-tenant, API-key scopes, private namespaces, tampered registry version) x TS SDK, Python SDK, CLI. `make console-e2e`: 60 mock flows + 14 real-stack Playwright tests (SSO, XSS, CSRF, cross-tenant, bundle scan). `make e2e` runs both. 6 wiring mutants (`e2e/mutation_phase7.py`).
- Defects found only by this wiring and fixed: AGIL `explainRun` asked the run service for 1000 events (limit 200); console replay used mock-only event names; the sign-in form was blocked by CSP `form-action 'self'`; the mutation audit hashed an undefined body.
- Honest gaps: self-approval is not modelled (the requester is the agent, NEEDS #272); signing is publisher tooling only (#273); publisher/staff marketplace steps are harness ops (#274); gateway is a dev composition (#275-#276); console admin pages are mock-verified only (#277); no real cross-site IdP (#278); no SSE fault injection (#280); CI job unrun remotely (#282).

## Phase 7 - Console and docs site (component D, `make console-e2e`)

**No frozen contract changed.** Status: Prototype, proven against a mock API (NEEDS #242-#258; ADRs 0050-0052; `docs/spec/console.md`).

- `packages/ui`: accessible component kit (Button, fields, Table, Dialog, Tabs, Badge, Toast, CodeEditor, Timeline, DiffView, EmptyState, ErrorBoundary), light/dark tokens, jest-axe tests.
- `apps/console` (Next.js 16): blueprints with live ABL diagnostics (line/column), runs with SSE timeline, replay scrubber and budget gauges, approvals (evidence, SLA, confirm, self-approval refused), policies (test panel, diff-gated activation), audit explorer with server plus in-browser hash-chain verification, usage (SVG), admin (one-time key reveal, write-only BYO keys, budgets, SSO/region), marketplace with permission-diff consent, AGIL explanation panel; same-origin BFF with CSRF and path allow-list, nonce CSP, role-aware UI, dark mode, responsive.
- `apps/docs-site`: static, deterministic docs from `docs/`, OpenAPI reference, ADR index, link checker.
- Tests: 78 console logic tests (`lib/` ~99%), 16 UI tests, 10 docs tests, 56 Playwright flows.

## Phase 7 - Registry and marketplace (component B)

- `services/registry` (`@axis/registry`): immutable semver blueprint versions per tenant namespace, ABL content hash, detached Ed25519 signatures with
  a per-namespace key registry (add/rotate/revoke, effective times, compromised vs retired), in-toto/DSSE provenance, verify-on-resolve (fail closed, no
  silent fallback), range resolution checked against the reference `semver`, typosquat/dependency-confusion guards, yank/deprecate, Postgres store with
  forced owner-checked RLS (migration 0020) + memory port (ADR 0030).
- `services/marketplace` (`@axis/marketplace`): publisher verification workflow, security review state machine with a static capability scan, listings
  and an anonymous catalog, consented installs (permission diff, digest-bound consent, pinned reference, deny-by-default policy pack stub), updates with
  re-consent on widening, takedown, `marketplace_installs` metering hook (migration 0021, ADR 0031). Dev servers are non-production. NEEDS #260-#271.

## Phase 6 - Independent review fixes (ADR 0023)

- Fixed: admin to owner via an admin-controlled IdP link (`sso.manage` now owner-only) and e-mail linking that never bound an identity;
  unbounded synchronous `opa` work on policy publish; stale kernel bundle after concurrent activations; builders could overwrite or delete
  other members' BYO model keys; budget limits that overflowed the runtime.
- Fixed (billing): tenant id spelling in lock keys and hashes, lost webhook retries after a failed handler, usage pushed from open periods,
  audit events for refused adjustments, a meter-wide allowance granted per model class. Open items: `docs/NEEDS.md` #206-#213.

## Phase 6 - SaaS platform integration (component C, `make e2e-phase6`)

Wires the control plane (A) and billing (B) into one path with the Risk Kernel and the runtime (ADR 0022). **No frozen contract changed**
(no migration, proto, OpenAPI or audit event type). Status: Prototype wiring, proven by an e2e that uses fakes at the IdP, KMS, DNS, model
provider and payment provider only.

- **A tenant signs up via SSO and runs its own policy.** Platform signup, SSO login through the fake IdP, admin calls over `/admin/v1`: BYO model key,
  policy pack (validated and compiled by the policy toolchain), budget. The tenant's active packs are compiled and written as a per-tenant bundle
  (`PolicyBundlePublisher`/`FileBundleSink`); the kernel dev process serves each tenant its own (`TenantBundleEngine`) and DENIES one whose bundle
  is missing or corrupt. The e2e shows the same agent denied under baseline-deny alone, allowed after the tenant activates a pack, and the tenant's
  own priority DENY enforced; audit rows carry the activated policy version.
- **BYO key and budgets reach the run.** `HttpSecretStore` (the provider is called with the key the admin configured) and `TenantBudgets` (the control
  plane's tenant token/cost hard caps stop runs through the TKI ledger; blueprint caps can only be tightened). Closes the budget half of NEEDS #191 and the client half of #186.
- **Metering wired.** `RunDeps.usage` forwards each run's billing projection; denied actions are not billed, a cache hit bills zero tokens; the ledger equals
  totals recomputed from the model provider's counts, the audit chain and the run logs; period close, seal verification, invoice vs independent rating,
  clean reconciliation against the Stripe fake, and injected duplicate/dropped/altered provider records reported with nothing repaired.
- **Negative paths** (21 scenarios in `e2e/test_phase6_saas.py`): viewer/builder/billing RBAC, tenant B admin against tenant A (404s, never data), API key
  scope/rotate/revoke/expiry, SCIM deprovision revoking sessions and keys, region-pinned writes (421), live Stripe keys refused, replayed/conflicting/forged
  usage, a `dedicated_db` tenant's audit in the second database (fail-closed without a pool), kernel DENY without a bundle.
- **Two real defects found by the e2e and fixed** (with unit regressions): runs stopped by a budget trip or kill were cancelled mid-emission and never billed;
  fractional budgets (`cost_usd: 0.001`) were refused as "audit unavailable" because the admin audit hashed with the integer-only canonicalizer.
- `e2e/mutation_phase6.py`: 12 wiring mutants (plus the cap-merge mutant killed by a unit test) (skip tenant policy load, bill denied actions, tenant from body, skip dedupe, accept live key, ...), see the report for the result.
- **Honest gaps:** NEEDS #197-#205 (file-based dev bundle delivery, in-memory untimed budget ledger, static dev credentials, usage emitted once at run end with no outbox,
  accuracy covers tokens/tools/runtime only, payment fake not Stripe-shaped HTTP, operator steps in the harness, placement routes the admin audit only and moves no data,
  harness-only ops surface) plus the open parts of #179-#195 (no real WorkOS/KMS/DNS/Stripe/ClickHouse; retention not enforced). `pnpm cov` can be red once under
  full-parallel load (#196).

## Phase 6 - Billing and usage ledger (component B, `services/billing`)

Additive migration `0008_billing.sql` (ADR 0018; contracts otherwise frozen; the integrating branch renumbers on collision) and an
ADR for Stripe test mode only (0041). Status: Prototype (library + loopback dev server; no live Stripe, ClickHouse, KMS or tax).

- **Usage ledger** (`@axis/billing`): append-only, idempotent per (tenant, source event), conflicting replays rejected and reported,
  integer micro-units (bigint, +-(2^53-1)), seven meters with dimensions, late/out-of-order events, UTC hourly/daily/monthly
  rollups, monthly period close with a hash-chained, signed seal; a late event for a closed month lands in the next period. Postgres
  (forced RLS, insert-only for everyone, DB trigger refusing inserts into a sealed period) and in-memory implementations share one
  contract suite; ClickHouse sink interface + fake.
- **Emitters.** Pure mapping from run events to usage (`model_call` tokens with cached tokens free, `tool_call_result`, `voice_call`,
  `process_transition`); a result is billed only if the same run log holds an ALLOW decision for its `action_id`, so denied,
  blocked and failed actions are never billed. Python `HttpUsageEmitter` (`runtime/.../usage.py`) forwards a whitelisted
  projection (no content); a golden fixture is checked from both languages.
- **Rating.** Versioned price books, graduated tiers, included quantities, commit true-up, proration, credits; integer rounding rules
  R1-R4 (`docs/spec/billing.md`); line items always sum to the invoice total (property-tested).
- **Stripe, test mode only.** `PaymentProvider` + fake; `StripePaymentProvider` over an injected transport refuses live keys and
  live-mode responses, sends an idempotency key on every mutation; webhook signature verification (HMAC, constant-time, tolerance).
- **Reconciliation** (ledger vs provider usage vs invoice lines; read-only) and an audited adjustment API; tenant-scoped read-only
  statement/usage endpoints on a dev server.
- **Verified:** 125 TypeScript tests on real Postgres 16 (see the report for coverage), `scripts-mutation.mjs` safety mutants,
  Python emitter tests, bypass scanner entry for `usage.py` only. NEEDS 163-178.

## Phase 6 - Control plane (component A, `services/control-plane`)

Prototype: built against fakes (IdP, KMS, DNS) and a real Postgres 16. Additive migration `0009_control_plane` (ADR 0020, `FREEZE.json`
regenerated); frozen OpenAPI/proto/audit contracts unchanged (ADR 0021: the admin API is an internal `/admin/v1`, NEEDS #189).

- IdP port with a FAKE; SSO callback (sealed login cookie, state, PKCE, nonce, org match, safe return URL), JIT limited to verified domains,
  signed short-lived sessions with rotating refresh and server-side revocation; SCIM 2.0 Users/Groups with deprovision-revokes.
- RBAC + ABAC on the policy toolchain (`policies/control-plane`, 73 golden cases in `make policy-test`), fail-closed; every admin mutation audited in the tenant chain.
- Tenant admin: signup, members/roles, API keys, BYO keys (envelope encryption), policy pack assignment, budgets, retention, region pinning; `TenantRouter` over shared / dedicated database tiers.
- 204 tests (memory and Postgres stores), 98% lines; `pnpm mutation`: 95 safety mutants killed. Gaps: NEEDS #179-#195.

## Phase 5 - Channels and voice (e2e integration)

Components A (channels service) and B (voice pipeline) were built as libraries; this entry is the integration (component C, ADR
0017). **No frozen contract changed** (no migration, proto, OpenAPI or audit event type).

- **Inbound message to agent run.** The gateway's `onMessage` is now `InboxQueue.handler`; the runtime's `ChannelAgentRunner` takes the
  verified messages of ITS tenant (bearer token fixes the tenant), fetches the conversation across channels and runs the agent the
  route names. The inbound audit event's trace id becomes the run's trace id. A dev bridge (in-memory inbox, no ack).
- **Gated reply.** `RunDeps.channels` (a `ChannelWiring`) builds a per-run sender bound to the run's tenant, run id and trace;
  `RunDeps.reply` sends the root agent's output as a `MessageSend` named `channel.reply` through the executor, so the real Risk Kernel
  decides it. A DENY, a gate error or a kill-switch sends nothing and shows up in `RunResult.reply`. A message the model composes
  through a channel tool is a different tool name and a separate decision.
- **Voice transcripts in the audit chain (NEEDS #140 closed with caveats).** `TranscriptWriter` appends each call and turn event to
  the tenant chain before persisting it (fail closed), through `POST /v1/channels/transcript-events` on the channels service, using the
  existing event shape (`lifecycle` / `message_send`, `voice.call.*` / `voice.turn.*`, hashes and sizes only, on the call's trace).
- **`make e2e-phase5`** (+ CI job `e2e-phase5`, unrun remotely): 25 tests on the real kernel (gRPC, OPA Wasm), Postgres audit chain
  and channels gateway. The same blueprint answers on web, Slack, SMS and email and over a voice call (consent notice, barge-in,
  PHI) with one audit trace per turn or call; a linked identity continues its conversation on another channel and unlinked
  identities share nothing; forged, stale, replayed and unrouted webhooks are rejected, audited and start no run; tenant B cannot
  reach tenant A's agent, queue or conversation; a policy DENY and a kill-switch send nothing on any channel; PHI transcripts are
  redacted before persistence on a channel and on voice; outbound calls are limited by country and gated; a prompt injection that the
  scripted model obeys produces a follow-up tool call that the kernel denies. Chain verifies after every scenario.
- **Mutation-checked** (`e2e/mutation_phase5.py`, by hand): 11/11 mutants killed (gate skipped on the reply, reply tool renamed,
  unverified inbound, replay accepted, tenant dropped from the inbox, raw PHI transcript on a channel and on voice, voice
  transcript not mirrored, history withheld, outbound country allowlist off, consent skipped). The first run left one survivor (a
  shared inbox queue); the cross-tenant test now checks that A's runner cannot see B's QUEUED message.
- **Found by the real stack.** Transcript-event detail keys with digits (`notice_sha256`) failed the service's validation, which
  ended the call (fail closed, as designed; the validator was wrong). A policy DENY rule on a missing field matches (fail closed), so
  an SSN rule on `args.body` also denied outbound calls until it was scoped to channel messages. The channels gateway stores a plain
  SHA-256 of the raw inbound text in the chain, which a short PHI value can be confirmed against (NEEDS #151, not changed).
- **Gaps, stated plainly** (`docs/NEEDS.md` #147-#155 and the open #119-#146): the inbox is in memory with no ack or ordering and there
  is no production worker; no Temporal path for replies or voice; voice is not part of the end user's conversation (no voice route
  or caller identity); the voice audit relay is a dev HTTP hop and the e2e run log is in memory; the LLM, STT/TTS vendors, telephony
  and every provider transport are fakes (Teams and WhatsApp are not in the e2e); the voice e2e runs on the system clock; the CI job
  and the mutation script have not run remotely.

## Phase 4 - independent review (branch p4/review)

Adversarial review of the Phase 4 code by a reviewer who did not write it. Every fix has a test that fails without it.

- **Sandbox.** Every run shared uid `nobody`, so two simultaneous runs (two tenants) could read each other's code file and
  output and plant forged artifacts through the host's `/tmp`; each run now gets its own uid. Artifact capture held one open
  descriptor per pending directory (a directory flood exhausted the runtime's descriptors for every other run) and checked the
  total byte cap against the size seen at `stat`; it is now depth-first and checks bytes read.
- **Browser.** Redirect hops re-issued by the backend carried `Authorization` to another origin and kept a POST body after a
  301/302/303 turned the request into a GET; the Fetch redirect rules are applied. The URL guard refuses authorities that
  `urlsplit` and Chromium split differently.
- **Memory.** PHI-mode documents persisted `title`/`source` verbatim; the SSN net missed separators other than `-`, non-ASCII
  digits, zero-width characters and a labelled bare SSN; a PHI tenant's search query reached the embedder unscrubbed; a deduped
  write overwrote the row's data subject (DSAR forget then missed it). Child agents used the ROOT's agent-scope owner and
  knowledge bases, and a child of a PHI run could write non-PHI memory.
- **MCP.** Only the tool description was sanitised; every string of the input schema now is.
- **Bypass scanner (weakened by Phase 4, restored).** `from asyncio import create_subprocess_exec as spawn` and
  `getattr(asyncio, "open_connection")` passed in every module once the MCP transports widened `MEMBER_ALLOW`; exemptions covered
  whole rule families (e.g. `os.unlink` in `sandbox/artifacts.py`, `asyncio.open_connection` in the inbound MCP server); and the
  Phase 4 backends could be driven ungated from `run.py`. Imports/aliases/literal `getattr` names are checked, each exemption is
  pinned to the findings its file really has, and the `Backends` handle is guarded.
- Open items: `docs/NEEDS.md` #112-#118 (and the narrowed #109).

## Phase 4 - Memory, tools and execution surfaces (e2e integration)

Components A-D (memory service, MCP client/server, code sandbox, browser workers) were built as libraries; this entry is the
integration (component E, ADR 0014). **No frozen contract changed.**

- **Run loop wiring.** ABL `memory.*` flags and knowledge bases reach the runtime (`RuntimeManifest.memory`) and build a per-run
  `HttpMemoryBackend` / `MemoryRagRetriever` (`RunDeps.memory`, `principal`, `session_id`); the model gets `memory_write` (gated
  `memory_write`) and `memory_search` (a new `MemoryRead` action, gated as `tool_call` kind `memory:read`). MCP: `check_manifest` and
  `definitions_for` run at spawn (an invalid manifest fails before any model call) and the model sees the server's schemas. Code and
  browser tools have fixed model-facing definitions; `RunDeps.browser` gives each run one `BrowserWorker` (policy from
  `static_policies`, no ABL field added) that is closed when the run ends. NEXUS now carries the run's principal and the rag stage's
  passages reach the model (they were dropped whenever the agent loop supplied messages).
- **`make e2e-phase4`** (+ CI job `e2e-phase4`, unrun remotely): 17 scenarios through the real Risk Kernel (gRPC), OPA Wasm policy
  pack, Postgres audit chain, memory service on Postgres+pgvector, stdio MCP server, inbound MCP HTTP server, real sandbox namespaces
  and real Chromium. Allow path for all four tools in one run with a decision row per call (gate requests == run-log decisions ==
  audit rows, the run log points at those rows); a DENY path per tool (MCP write, shell, foreign browser host, unredacted PHI) that
  performs nothing; code `network=true` denied before the sandbox runs; PHI agents get no code or browser; memory ACL (principal A
  cannot retrieve B's document by rag or by tool) and cross-tenant isolation through the whole stack; tool-scoped kernel
  kill-switch stops each of the five tools and releasing it restores them; prompt injection in an MCP result and in a browser page
  (the scripted model obeys it) produces a follow-up call that is gated and denied; an inbound MCP client is authenticated, gated
  and audited; an unreachable kernel denies all four tool kinds. Chain verifies after every scenario.
- **Mutation-checked.** Forcing ALLOW on `code_exec`, `browser_exec`, `mcp_call`, `memory_write` or `tool_call` each fails 5-9 of
  the 17 e2e scenarios and 7-14 bypass tests.
- **Defects the real stack found, fixed.** (1) Inbound MCP calls were all denied ("audit unavailable"): a `system` actor carried a
  pid that the audit table's CHECK rejects. (2) The sandbox `isolation` map, usage and duration never reached the event log. (3)
  `LlmStage` dropped retrieved passages whenever messages were supplied, and the run never set the NEXUS principal. (4) ABL v1
  cannot name a registered MCP server (URI-typed `mcpServer`): `mcp://<name>` is now the documented runtime convention.
- **Gaps, stated plainly** (`docs/NEEDS.md` #74-#111): the memory service is a loopback dev surface with a hash embedder; the
  sandbox is process-level and not a security boundary; Chromium egress is enforced in-process; MCP was only exercised against
  in-repo fakes; the LLM in the e2e is scripted; rag retrieval is not a gated action; policy cannot match `context.inbound`; the
  Temporal path is not wired; children share the root's memory/browser/principal; the CI job has never run.
- **Housekeeping.** NEEDS rows from the four component branches (100-106, 200-206, 300-308, 400-407) are renumbered #74-#104
  (memory #74-#81, MCP #82-#88, sandbox #89-#95, browser #96-#104) and every reference is updated.

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

### Phase 3 review round

Independent review found and fixed: ReDoS in tenant NEXUS rules, restarts resetting child budgets (hard cap exceedable), cache hits bypassing the gate (now replayed through the Risk Kernel), approval waits holding scheduler slots, unbounded approval-record age (15 min bound), silent truncation of a malformed HMAC key. Open: NEEDS #46, #63, #65, #69-#73.

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
