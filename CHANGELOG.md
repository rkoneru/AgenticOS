# Changelog

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
- **Gaps, stated plainly** (`docs/NEEDS.md` #[74]-#[111]): the memory service is a loopback dev surface with a hash embedder; the
  sandbox is process-level and not a security boundary; Chromium egress is enforced in-process; MCP was only exercised against
  in-repo fakes; the LLM in the e2e is scripted; rag retrieval is not a gated action; policy cannot match `context.inbound`; the
  Temporal path is not wired; children share the root's memory/browser/principal; the CI job has never run.
- **Housekeeping.** NEEDS rows from the four component branches (100-106, 200-206, 300-308, 400-407) are renumbered #[74]-#[104]
  (memory #[74]-#[81], MCP #[82]-#[88], sandbox #[89]-#[95], browser #[96]-#[104]) and every reference is updated.

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
