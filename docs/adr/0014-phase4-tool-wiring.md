# ADR 0014: Phase 4 integration (memory, MCP, code and browser tools in the run loop)

Status: accepted · Phase 4 component E · **No frozen contract changed** (`packages/contracts/FREEZE.json` untouched: no ABL
field, policy-DSL field, proto, OpenAPI path or migration was added)

## Context

Memory (A), MCP client/server (B), the code sandbox (C) and browser workers (D) were built as libraries. Each component report left
the run-loop wiring to E: nothing built the memory backend from the manifest, `run.py` never called `definitions_for` /
`check_manifest`, the code and browser tools had no model-facing schema, and there was no per-run browser worker. The Phase 4 exit
is one real run in which an agent uses all four, through the real Risk Kernel and the Postgres audit chain, with a decision row for
every call. Three pieces of the frozen ABL v1 get in the way (below), so the wiring uses documented runtime-side conventions
instead of new ABL fields.

## Decisions

1. **ABL `memory.*` reaches the runtime.** `RuntimeManifest.memory` (`MemorySpec`: `run`, `session`, `long_term`,
   `knowledge_bases`) is parsed from the manifest the compiler already emits (it was silently dropped). A manifest without a
   `memory` key means all-off. Memory is exposed to a process only when the host supplies `RunDeps.memory` (the service
   connection) **and** a flag or knowledge base is set; `RunDeps.memory` together with `backends.memory` is an error.
2. **Two memory tools, minimum model-controlled surface.** `memory_write(scope, content, metadata?, subject?, ttl_seconds?)` is a
   `MemoryWrite` (enforcement point `memory_write`, `tool.kind = memory:<scope>`). `memory_search(query, scope?, limit?)` is a new
   `MemoryRead` action. Scope must be one the manifest flags allow (`run`, `session`, `long_term`; `kb` for search; never `tenant`).
   **ACL, `phi`, owner references and the principal are wiring, never model arguments**: an unexpected argument is a tool error and
   nothing reaches the gate. `phi` is set from the manifest, so a PHI agent's writes are redacted by the service before embedding.
3. **A memory read is gated as a `tool_call` with `tool.kind = memory:read`.** The frozen policy DSL and the audit event enum have no
   `memory_read` enforcement point and adding one needs the freeze procedure. `side_effects` is `read`, so a pack's ordinary
   read-allow rule covers it and a pack can still deny it by kind. The gate sees scopes, limit and the query's length and SHA-256,
   never the query text; the run log keeps hits as ids, scores and content hashes (the agent gets the text).
4. **Who is asking.** `RunDeps.principal` (+ `principal_groups`, `session_id`) is the ACL principal of every memory call of the run
   (default `agent:<name>`). It is also set on NEXUS `RouteRequest.principal`, which the run loop used to leave empty (so the real
   retriever, which refuses an empty principal, could never have served a run). `RunContext.memory_retriever` is the
   `MemoryRagRetriever` for the manifest's knowledge bases; the host puts it in a `RagStage`.
5. **Retrieved passages now reach the model.** `LlmStage` ignored `state.retrieved` whenever the agent loop supplied its own
   `messages` (always, in a run), so the rag stage could only ever answer extractively. It now inserts one `Context:` system message
   after the leading system messages. Passages are data for the model, never instructions.
6. **MCP: validate and describe at spawn.** `AgentProcess` runs `_prepare_tools()` before `init_complete`: when the backend
   implements `McpManifestSource` (`TenantMcpClient.check_manifest` + `definitions_for`), the registry must allow every server and
   tool the manifest names, and a tool the server does not offer is a manifest error. Any failure is `FAILED` with `init:` detail and
   no model call is made. The model sees the server's sanitised schema. A bare `McpClient` (the Phase 2 `HttpMcpClient`) offers
   neither and keeps the old behaviour.
7. **ABL v1 cannot name a registered MCP server, so `mcp://<name>` is a runtime convention.** The frozen schema types `mcpServer` as a
   URI and `ref` as a versioned artifact ref (`name@range`), but the tenant registry is keyed by a short name and a remote tool
   name may contain `_`. `mcpServer: "mcp://kb"` means the registry entry `kb`; any other value is passed through verbatim and fails
   to resolve (fail closed). The remote tool name is the tool's own `name` (ABL names are DNS labels; `ref` is not used for MCP).
   A URL-to-registry mapping for `https://` servers is not built.
8. **Code and browser get fixed model-facing definitions** (`tooldefs.py`) unless a function registry entry overrides them. The code
   tool's `network` flag stays wiring (an agent cannot set it); policy decides on `args.network`, `args.language` and `data.phi`.
9. **Browser: one worker per run, policy from an operator-held provider.** `RunDeps.browser` is a `BrowserWorkerFactory`;
   `start_agent` builds `for_run(tenant, agent=<manifest name>, run_id)`, installs it as `backends.browser`, and closes it when the run
   ends (`RunContext.closers`, also when start-up fails after the worker exists). The factory's `(tenant, agent) -> BrowserPolicy`
   provider is `browser.worker.static_policies({(tenant, agent): tool-config})`: parsed eagerly, unlisted pair = no policy = every
   request blocked. **No ABL field was added**: `allowed_domains` per agent is operator/tenant configuration that must not be
   editable by the agent author, and a post-freeze ABL change would need the ADR + freeze procedure for a feature whose home (a
   tenant policy API, NEEDS #8) does not exist yet. The action's `target_url` is built by the worker from its own page state; any
   `target_url` the model supplies is dropped.
10. **The e2e found two real defects in earlier components, fixed here.** (a) The sandbox result reaches the event log as a dict, so
    the `isolation` map, usage and duration were dropped from the evidence the spec promised; `_summarise_result_dict` now keeps them
    (no output text). (b) Inbound MCP calls (wire actor `system`) carried the runtime's `pid`, which the audit table rejects
    (`actor_type = 'agent'` iff `actor_pid` is set), so the kernel answered "audit unavailable" and **every inbound call was
    denied**; the gate client now sends a pid only for agent actors. The kernel accepts the combination and the database
    rejects it: NEEDS #X7.
11. **Policy cannot see `context.inbound`.** The policy compiler's context roots do not include `inbound`, so a pack cannot match
    on it. The e2e pack denies inbound writes with `actor.type eq system` (inbound MCP clients are the only `system` actors today).
    The kernel does receive `context.inbound`; the e2e asserts the runtime sends it. NEEDS #X2.

## Consequences

- Memory retrieval through the NEXUS rag stage is a read of tenant data that is not a gate decision (extractive answers
  and passages): service-side ACL and the stage's re-check are the only controls. NEEDS #X1.
- The Temporal path builds its own executor and does none of this wiring (spawn-time MCP checks, memory, browser worker): NEEDS #X4,
  same family as #66.
- Children of a run share the root's memory backend (so `agent`-scope memory belongs to the root agent's name), its browser worker
  (one page per run) and its principal: NEEDS #X5.
- The e2e is **evidence for the wiring, not for the components' production readiness**: the LLM, the embedder and the MCP server are
  fakes, the browser talks to a local fixture site, the sandbox is process-level. NEEDS #X6.
- Mutation checks: skipping the gate (forcing ALLOW) on each of `code_exec`, `browser_exec`, `mcp_call`, `memory_write` and
  `tool_call` fails 5-9 of the 17 e2e scenarios and 7-14 bypass tests each. Removing the principal from the NEXUS request fails the
  e2e; removing the spawn-time MCP manifest check fails two unit tests (the e2e still passes because `definitions_for` also resolves
  the registry entry: the shadowing check is only covered by unit tests).
