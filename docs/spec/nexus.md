# NEXUS and MPM stub (Python runtime)

Status: **Prototype** (in-memory cache, tracer and run log; wired into the run loop and proven in `make e2e-phase3`; see
`docs/NEEDS.md` #41-47, #65). Decision record: `docs/adr/0012-phase3-integration.md`.
Code: `runtime/src/axis_runtime/nexus/`. Tests: `runtime/tests/test_nexus_*.py`.

NEXUS decides how a request is answered as cheaply as is safe: **cache -> rules -> MPM -> RAG -> LLM**. The stages that run,
and their order, come from the manifest's `routing.stages` (`RuntimeManifest.routing_stages`, default `["llm"]`).

## Pipeline contract

- A `Stage` has a `name` and `async run(request, state) -> Hit | Miss`.
- `Hit(answer, cost, confidence, tokens, cacheable, tool_calls, cache_key_hash, meta)`. The first Hit short-circuits; later
  stages never run.
- `Miss(reason, cost, tokens, blocked, cache_key_hash, context)`. A miss still carries the cost of the attempt (attributed to that
  stage). `context` passages (RAG) are accumulated into `RouteState.retrieved` for later stages (the LLM prompt).
- `NexusRouter.from_manifest(manifest, available)` builds the pipeline in declared order. A declared stage with no implementation,
  an unknown or duplicate stage, or an `llm` stage that is not last is a `NexusConfigError` (fail closed, never silently dropped).
- `RouteResult`: `status` (`hit` | `blocked` | `exhausted`), `answer`, `hit_stage`, per-stage `StageRecord`s, `total_cost_usd`,
  `total_tokens`, `cost_by_stage`, `tool_calls`. An exhausted route has no answer; nothing is ever fabricated.

## Robustness and the gate

- A stage that raises (recorded by exception type name only, never the message), exceeds `stage_timeout_s`, or returns a
  malformed Hit (confidence outside [0, 1], negative cost/tokens) is a **miss** and the pipeline falls through. `CancelledError`
  propagates.
- Routing never performs an action. The **LLM stage** is the final fallback and only builds a `ModelCall` and passes it to the
  `ActionRunner` (the `ActionExecutor`), so it is gated by the Risk Kernel and reaches providers only via the `ModelGateway`
  (invariants 1 and 5). A gate DENY, gate error, or approval-pending yields a **blocked** route (`blocked_reason`), which is
  terminal and never retried. Tool calls in the model's response are returned in `RouteResult.tool_calls` for the caller to
  dispatch through the executor; NEXUS does not run them.
- A routing decision therefore cannot bypass the gate. `test_bypass.py` / `bypass_scan.py` are unchanged and cover the package
  (no new imports or exemptions were needed).

## Telemetry

- Spans (internal `Tracer` interface, OTel vocabulary; `InMemoryTracer` is the only exporter): `nexus.route` with child
  `nexus.stage.<name>`. Attributes: `nexus.stage`, `nexus.hit`, `nexus.latency_ms`, `nexus.tokens`, `nexus.cost_usd`,
  `nexus.reason`, `nexus.cache_key_hash` (16 hex chars of a tenant-salted SHA-256), `nexus.tenant_id`, `nexus.trace_id`.
  **Raw prompts and answers are never in a span or event** (tested).
- Events through the injected `EventSink`: `nexus_stage` per stage (stage, outcome, reason, latency, tokens, cost, hash,
  confidence) and `nexus_route` per route (status, hit stage, totals, `cost_by_stage`). Sink failures are counted in
  `RouteResult.sink_errors` and never break routing. Appending them to the audit/run log is NEEDS #45.

## Cache stage

- Store API is `(tenant_id, key)`; internally `tenant_id -> bounded LRU`, so a cross-tenant hit is structurally impossible. The key
  digest also includes tenant, principal (default; `scope_principal=False` to share within a tenant), agent name/version, system
  prompt hash and the whitespace-normalised prompt. Property test: 300 random tenant-1 writes never hit for tenant 2.
- TTL on a monotonic clock. **No caching when `request.phi`** (no read, no write; the stage reports a `phi` miss), when the Hit is
  `cacheable=False`, or when the response carries tool calls. Rule hits and cache hits are not written back.
- Only stages **before** the hit learn from it (`write_back`).

## Rules stage

Ordered rule list, first match wins: `exact` (case/whitespace-insensitive), `regex`, `intent` (matches `request.intent`). A rule
with `tenant_id` applies only to that tenant. Regexes are tenant input: length-capped, nested quantifiers / backreferences /
lookarounds rejected, input truncated to 4096 chars. This is a mitigation, not a ReDoS proof (NEEDS #46).

## MPM stub

- `MicroModel` (id, capabilities, `async predict(tenant_id, prompt) -> Prediction | None`; `None` = abstain).
- `MicroModelRegistry`: `register` (platform-wide or per tenant), `get`, `list(tenant, capability)`, `unregister`. A tenant sees
  its own and platform models, never another tenant's; a tenant model shadows a platform model of the same id.
- `MpmStage(registry, threshold)`: consults every model for `request.capability`, answers with the most confident prediction if
  `confidence >= threshold`, else falls through (cost of all consulted models is attributed to `mpm`). A crashing model is skipped.
- Mocks: `KeywordModel` (deterministic keyword overlap), `FixedModel`. No real model exists (NEEDS #41).
- `benchmark(model, dataset, clock, threshold)` returns `BenchmarkReport` (accuracy, coverage, selective accuracy, total/mean
  cost, mean/p95 latency). Everything is computed from observed predictions and an injected clock; nothing is hard-coded.

## RAG stage

`Retriever.retrieve(tenant_id, principal, query, limit)` always carries the tenant and ACL principal. `InMemoryRetriever` is a
deterministic lexical fake that filters by both. `RagStage` re-checks both on whatever the retriever returns (a misbehaving
retriever cannot widen access). A passage scoring >= `answer_threshold` answers extractively; lower-scoring passages ride along as
LLM context. Real retrieval is Phase 4 (NEEDS #42).

## In the run loop (Phase 3)

- `RunDeps.nexus_factory(ctx) -> NexusRouter` builds the router per run; `ctx.runner` (the gated executor, budget-wrapped under
  TKI) is what its `LlmStage` calls, and `ctx.nexus_event_sink()` appends events to the run log. When set, **every model step of
  every agent in the run** is routed (`routing.stages`, e.g. `cache -> rules -> llm`) instead of calling the model directly.
- `RouteRequest` gained additive `messages` and `tools`: the agent loop's whole conversation and tool definitions. The LLM stage
  sends exactly those (plus the same `provider/model` action name the direct path uses), `prompt` stays the latest user text for the
  rules stage, and the **cache key covers the whole conversation and tool set**, so a hit is replayed only for an identical call.
  Responses with tool calls are never cached; PHI runs never cache.
- Outcome mapping (same as the direct path): LLM stage `blocked` on a gate DENY -> process exit `policy_denied`; approval pending ->
  run parks (`awaiting_approval`); a failed model call or exhausted route -> `failed`.
- **Cache hits are gated (review fix, NEEDS #65):** `RunContext` replays a cached answer as the very `model_call` it substitutes
  (`ModelCall(replay=...)`: same name and arguments, gated and audited, `perform` returns the cached text, provider `nexus-cache`,
  zero tokens and cost, no budget reservation). A kill-switch or DENY rule stops it; a redaction applies to it. **Rules (and MPM/RAG)
  hits are still not gated or audited** (static tenant configuration / retrieval, no model output). Tool calls from a model answer
  are dispatched through the executor by the agent loop.
- **Run log:** `nexus_stage` (stage, `hit`/`miss`, reason, latency, tokens, `cost_usd` as a decimal string, cache-key hash,
  confidence) and `nexus_route` (status, hit stage, totals, `cost_by_stage`) are additive run-event types (ADR 0012), folded into
  `RunState.nexus_stages` / `nexus_routes`, hash-chained and replayable like every other event. Not in the audit chain (frozen
  contract; NEEDS #45).
- **Trace:** `InMemoryTracer.export()` returns JSON spans (`span_id`, `parent_span_id`, `name`, `attributes`, `ok`): `nexus.route`
  with a `nexus.stage.<name>` child per attempted stage carrying `nexus.hit`, `nexus.cost_usd`, `nexus.tokens`,
  `nexus.latency_ms`; `nexus.trace_id` equals the run's trace id (the audit chain's `trace_id`). No OTLP exporter yet (NEXUS #44).
- Evidence: `runtime/tests/test_run_nexus.py` and `e2e/test_phase3_orchestration.py` (second identical call: cache hit, no gate
  call, no provider call, route cost 0 against > 0 for the first).

## Not covered

See `docs/NEEDS.md` #41-47, #65: real micro-models, real RAG, shared cache backends, an OTLP exporter, the audit-chain append of
NEXUS events, linear-time regex, ABL parameters for stage configuration, and gating of cache/rules hits.
