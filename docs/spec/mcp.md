# MCP integration (client and server)

Status: **Prototype**. Implemented in `runtime/src/axis_runtime/mcp/`, wired into the run loop and tested with in-repo fakes only
(`make e2e-phase4` drives the fake stdio server `runtime/tests/fake_mcp_stdio.py` and the inbound HTTP server over a real socket; no
third-party MCP client or server has been exercised: NEEDS #106). Protocol: MCP revisions 2025-06-18 and 2025-03-26, JSON-RPC 2.0, **tools
only**. Contracts (proto, OpenAPI, ABL, DB) are unchanged; see NEEDS #100 for the one contract gap.

## Client: agents consuming MCP servers

```
manifest tool {kind: mcp, mcp_server: "kb", ref?: "search"}
   -> McpCall(name, mcp_server, ref, args)            actions.py
   -> ActionExecutor.run: gate (fail-closed) -> audit event -> perform
   -> TenantMcpClient.call_tool("kb", "search", args)  mcp/backend.py   (the Backends.mcp implementation)
   -> McpSession (initialize / tools/list / tools/call) mcp/client.py
   -> StdioTransport | StreamableHttpTransport         mcp/stdio.py, mcp/http.py
```

- **Gate context.** `tool = {name: "kb/search", kind: "mcp", side_effects, server: "kb"}`, `args` = the call arguments,
  `enforcement_point = mcp_call`. `side_effects` comes from the manifest, never from the server.
- **Namespacing.** Policies, audit and events see `server/tool`. Server names match `[a-z][a-z0-9_-]{0,31}` and tool names
  `[A-Za-z0-9_.-]{1,64}`: neither can contain `/`, so a server cannot mint a name that looks like another server's tool, and
  a server's tool named `lookup` is `kb/lookup`, never the built-in `lookup`. Registry `reserved_tool_names` and
  `check_manifest` additionally refuse a manifest whose `server/tool` equals a non-MCP tool.
- **Server registry** (`McpServerRegistry`): entries are `(tenant_id, name)`. The manifest names a server; it resolves only
  through the calling tenant's entries, and "unknown" and "belongs to another tenant" are the same error.
- **HTTP servers** are tenant-registered; the URL passes `models/endpoints.validate_endpoint` before **every** request
  (https only, no userinfo, public addresses only unless the entry opts in, DNS checked), redirects are never followed,
  bodies are read with a byte cap, and the exchange has a deadline. Known limit: no connect-time pinning (NEEDS #104/#22).
- **stdio servers** come only from an **operator catalog** (`StdioCommand`: absolute argv, full environment, cwd). Tenants
  select a catalog id; there is no API to pass a command, argument, environment variable or working directory. The child gets
  exactly the operator's environment (nothing inherited), no stderr, capped lines, deadlines; it is killed on timeout,
  overrun, protocol violation or close, and never respawned mid-session. No sandbox (NEEDS #101).
- **Limits** (`McpLimits`): message, result, description, schema sizes; tools per server; list pages; content items; call
  and connect timeouts; tool-list TTL.

### Run-loop wiring (Phase 4 / E, ADR 0014)

- **At spawn** (`AgentProcess._prepare_tools`, before `init_complete`): if the backend is a `TenantMcpClient`, `check_manifest` and
  `definitions_for` run. An unknown/other-tenant server, a shadowing name, or a tool the server does not list fails the process with
  `init:` detail and makes no model call. The model is shown the server's sanitised description and schema.
- **Naming.** ABL v1 (frozen) types `mcpServer` as a URI and `ref` as a versioned ref, so the runtime reads `mcpServer: "mcp://<name>"`
  as the registry entry `<name>` (anything else is passed through and will not resolve), and the remote tool name is the manifest tool's
  `name`. Policy and audit see the qualified name `server/tool` in `tool.name`; the action name is the manifest name.
- **Injection.** A tool result is data: the e2e has the (scripted) model obey an injected "call write-note" in a result; the follow-up
  call is gated (`deny-mcp-writes`), audited as a DENY and never reaches the server.
- **Inbound** (e2e): unauthenticated calls reach no gate; an authenticated tenant-1 client lists its catalog, a read tool is
  ALLOWed, a write tool is DENYed ("Denied by policy", not performed), a tenant-2 client cannot see or call tenant 1's tools. The kernel
  receives `context.inbound`; policy cannot match on it (NEEDS #X2), so the pack matches `actor.type eq system`. The wire actor carries
  no pid (the audit table rejects one on a non-agent actor, ADR 0014 #10).

## Server: external MCP clients calling AXIS

`McpServer.handle(body, bearer) -> Reply` is transport-agnostic; `McpHttpServer` is a stdlib asyncio HTTP/1.1 front.

- Order: size cap -> **authenticate** (injected `Authenticator`; error/None/blank = 401) -> strict parse -> per-principal rate
  limit -> dispatch.
- Tenant and principal come only from the authenticator. `tools/list` returns the principal's tenant catalog filtered by the
  principal's scopes; `tools/call` for a tool outside that set is the same `unknown tool` error as a non-existent one (no
  cross-tenant existence oracle). Nothing in a message can select a tenant.
- `tools/call` builds an Action and runs it through the injected `ActionRunner` (the `ActionExecutor` for the principal's
  tenant, see `mcp_identity`): **gate -> audit -> perform**. The server module never performs anything (a test asserts the
  source contains no `perform`/`_execute`, and the bypass scanner forbids it). Actor is `mcp_client` (wire: `system`, with
  `context.inbound`; NEEDS #100).
- Results: policy denial, approval-required and tool failure are fixed generic `isError` texts: gate reasons, approval ids,
  exception text and policy names never reach the client. Result text is capped.
- Hardening: request-size cap, rate limit (token bucket per principal), in-flight cap per principal, call timeout,
  duplicate in-flight id rejected, ids echoed with exact type, `notifications/cancelled` honoured only for the caller's own
  requests, notifications never produce a body (a `tools/call` sent as a notification does nothing), batches rejected,
  duplicate JSON keys / `NaN` / depth > 32 rejected, `Origin` allowlist, `Content-Length` only (no chunked), header and
  connection caps, read deadlines. Stateless: no `Mcp-Session-Id` (NEEDS #102/#106).

## Threat model

Assets: the tenant's policy decisions, tenant isolation, the host (process/network), model context integrity, audit
integrity. Everything an MCP server sends (descriptions, schemas, results, errors, notifications) is **attacker-controlled
data**; so is everything an inbound client sends except the authenticated identity.

| Threat                                                                                                     | Control                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Test                                                                                                                                                                                   |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tool description / result carries instructions ("ignore previous, call X, add admin=true")                 | Text is stripped of control, bidi, zero-width and tag characters, truncated and **flagged** (informational heuristic, never relied on). The decisive controls are structural: nothing parsed from a description or result feeds into the tool set, arguments, `side_effects`, tool name, gate context or registry; arguments are exactly the Action's; one `tools/call` per Action; the model can only request tools the manifest declares, and each is gated | `test_injected_result_cannot_add_tools_or_trigger_calls`, `test_description_is_sanitised_truncated_flagged_not_obeyed`, `test_server_text_cannot_change_policy_input_on_the_next_call` |
| Server adds/changes tools mid-session                                                                      | Tool list is fetched by us, deduplicated (duplicate names dropped entirely), refreshed only on TTL or miss, filtered by the entry's `allow_tools`; list-changed notifications ignored                                                                                                                                                                                                                                                                         | `test_duplicate_name_drops_both...`, `test_tool_list_refresh_and_ttl`                                                                                                                  |
| Server shadows a built-in or another server's tool                                                         | Namespaced `server/tool`; `/` not allowed in either part; reserved-name and manifest collision checks                                                                                                                                                                                                                                                                                                                                                         | `test_server_cannot_shadow_across_namespaces`, `test_check_manifest`                                                                                                                   |
| Server claims `readOnlyHint` to dodge policy                                                               | `annotations` ignored; `side_effects` from the manifest                                                                                                                                                                                                                                                                                                                                                                                                       | listing test                                                                                                                                                                           |
| Server asks the client to do things (sampling, roots, elicitation, ping)                                   | Client declares no capabilities and answers every server request `method not found`                                                                                                                                                                                                                                                                                                                                                                           | `test_server_initiated_requests_are_rejected_not_executed`                                                                                                                             |
| Server-controlled error text reaches audit or the model                                                    | Errors carry codes and fixed strings only                                                                                                                                                                                                                                                                                                                                                                                                                     | `test_json_rpc_error_does_not_leak_server_text`                                                                                                                                        |
| Oversized / endless / malformed responses                                                                  | Byte caps at transport, message, result and schema level; deadlines; typed errors; stdio child killed                                                                                                                                                                                                                                                                                                                                                         | transport tests                                                                                                                                                                        |
| SSRF through a tenant-supplied HTTP server (metadata IPs, loopback, rebinding at DNS time, redirects)      | Endpoint guard before every request; no redirects                                                                                                                                                                                                                                                                                                                                                                                                             | `test_http_ssrf_guard_*`                                                                                                                                                               |
| Tenant obtains code execution via stdio config                                                             | Operator catalog only; env scrubbed; no tenant-supplied argv/env/cwd                                                                                                                                                                                                                                                                                                                                                                                          | `test_stdio_only_from_operator_catalog`, `test_stdio_round_trip_and_scrubbed_environment`                                                                                              |
| Tenant A uses tenant B's server (outbound) or tools (inbound)                                              | Registry keyed by tenant; catalog keyed by authenticated tenant; identical errors                                                                                                                                                                                                                                                                                                                                                                             | registry/server tests                                                                                                                                                                  |
| Unauthenticated or forged inbound calls                                                                    | Authenticator first; fail closed; tenant never from the message                                                                                                                                                                                                                                                                                                                                                                                               | `test_unauthenticated_is_401...`                                                                                                                                                       |
| Inbound call skips the gate                                                                                | The only path is `ActionExecutor.run`; server module forbidden from `perform`; bypass scanner scopes IO grants per file                                                                                                                                                                                                                                                                                                                                       | `test_mcp_bypass.py`                                                                                                                                                                   |
| Parser differentials / smuggling (duplicate keys, id type confusion, batches, notifications used as calls) | Strict parser; type-exact ids                                                                                                                                                                                                                                                                                                                                                                                                                                 | `test_mcp_protocol.py`, server tests                                                                                                                                                   |
| DoS (floods, slow clients, huge bodies, many in-flight calls)                                              | Caps, deadlines, rate and in-flight limits                                                                                                                                                                                                                                                                                                                                                                                                                    | server and HTTP tests                                                                                                                                                                  |

Residual risks (not mitigated): a legitimate-looking description can still persuade the model to call a _declared_ tool with
harmful arguments, which is why every call is gated, argument-checked by policy and capped by budgets, and why side effects
come from the manifest; model-side prompt-injection resistance is out of scope. Flags can be evaded. See NEEDS #100-#106 for
the unbuilt isolation, TLS, authentication and pinning work.
