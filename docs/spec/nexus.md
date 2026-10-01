# NEXUS and MPM stub (Python runtime)

Status: **Prototype** (tested with in-memory fakes; not wired into `run.py`; see `docs/NEEDS.md` #41-47).
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

## Not covered

See `docs/NEEDS.md` #41-47: real micro-models, real RAG, shared cache backends, OTel exporter, run-log/audit append of NEXUS
events, linear-time regex, and wiring into `run.py` / ABL parameters.
