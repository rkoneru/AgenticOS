# STRIDE: MCP client and server

Status: Prototype. Spec: `docs/spec/mcp.md`. Outbound: agents call MCP servers as `mcp_call` actions. Inbound: external MCP clients call AXIS (actor `mcp_client`, appears as `system` on the wire, NEEDS #82). Tool descriptions and results come from servers the tenant does not control.

## Assets

- The tenant's network and secrets (stdio children, HTTP endpoints, credentials to servers).
- Integrity of tool definitions shown to the model.
- The inbound surface: what an external client may invoke.

## Trust boundaries

1. Manifest to server: the tenant's registry must allow every server and tool a manifest names, or the process fails to spawn (`runtime/src/axis_runtime/mcp/backend.py`, `runtime/src/axis_runtime/mcp/config.py`).
2. Outbound HTTP: an SSRF guard validates every request; stdio servers come only from an operator catalog with a scrubbed environment (`runtime/src/axis_runtime/mcp/http.py`, `runtime/src/axis_runtime/mcp/stdio.py`).
3. Server to model: tool definitions and schemas are sanitised before the model sees them (`runtime/src/axis_runtime/mcp/client.py`); results are tool data.
4. Inbound HTTP: `Origin` allowlist, size and depth limits, authenticator interface (`runtime/src/axis_runtime/mcp/http_server.py`, `runtime/src/axis_runtime/mcp/server.py`).

## Data flow

Outbound: manifest tool -> `McpCall` action with `side_effects` from the manifest (never from the server) -> kernel -> client sends JSON-RPC -> result capped and returned as a tool message. Inbound: authenticated request -> tools/list or tools/call -> every call becomes a gated action with a `system` actor and the `inbound` context key.

## STRIDE

| Category               | Threat                                                                        | Mitigation (code path)                                                                                                                | Test                                                                        | Residual / NEEDS                                                       |
| ---------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Spoofing               | A server pretends to be another tool by changing names or definitions mid-run | Tool lists refresh on TTL or miss and the manifest names exactly the allowed tools (`runtime/src/axis_runtime/mcp/backend.py`)        | `runtime/tests/test_mcp_client.py`                                          | list-changed notifications ignored (NEEDS #88)                         |
| Spoofing               | An inbound client acts as another principal                                   | The `Authenticator` interface decides; the principal id goes in the gate context (`runtime/src/axis_runtime/mcp/server.py`)           | `runtime/tests/test_mcp_server.py`, `runtime/tests/test_mcp_http_server.py` | No real authenticator yet (NEEDS #85)                                  |
| Tampering              | A server returns a hostile or malformed JSON-RPC response                     | Strict protocol parsing: duplicate keys, `NaN`, depth over 32 rejected, size caps (`runtime/src/axis_runtime/mcp/protocol.py`)        | `runtime/tests/test_mcp_protocol.py`                                        | none known                                                             |
| Repudiation            | An MCP call without a record                                                  | Calls reach servers only through `McpCall` in the executor; bypass test over the module (`runtime/src/axis_runtime/mcp/backend.py`)   | `runtime/tests/test_mcp_bypass.py`, `runtime/tests/test_bypass.py`          | none known                                                             |
| Information disclosure | Environment or secrets leak into a stdio child, or out of it                  | Operator catalog only, absolute argv, empty-by-default environment, no stderr, capped lines (`runtime/src/axis_runtime/mcp/stdio.py`) | `runtime/tests/test_mcp_transports.py`                                      | The child is not sandboxed (NEEDS #83)                                 |
| Information disclosure | SSRF to internal addresses via a server URL                                   | Request-time guard on every request (`runtime/src/axis_runtime/mcp/http.py`)                                                          | `runtime/tests/test_mcp_transports.py`                                      | No connect-time IP pinning (NEEDS #86)                                 |
| Denial of service      | Slow, huge or endless server responses                                        | Deadlines, byte and line caps, kill on timeout (`runtime/src/axis_runtime/mcp/stdio.py`, `runtime/src/axis_runtime/mcp/http.py`)      | `runtime/tests/test_mcp_transports.py`                                      | Inbound HTTP has no TLS or pre-auth throttle (NEEDS #84)               |
| Elevation of privilege | A server labels a write tool as a read                                        | `side_effects` comes from the manifest, never from the server (`runtime/src/axis_runtime/mcp/backend.py`)                             | `runtime/tests/test_mcp_client.py`                                          | The manifest author's label is trusted by baseline policy (NEEDS #399) |
| Elevation of privilege | An inbound write is accepted because policy cannot see `inbound`              | The e2e pack denies write and external effects for actor type `system` (`e2e/policies/phase4-tools/pack.yaml`)                        | `e2e/test_phase4_tools.py`                                                  | Policy DSL cannot match `context.inbound` (NEEDS #106)                 |

## Prompt injection

MCP is a double channel: tool DESCRIPTIONS (shown to the model before any call) and tool RESULTS (after). Controls: schemas and descriptions are sanitised for invisible, tag-block and bidi characters and length (`runtime/src/axis_runtime/mcp/client.py`, NEEDS #117 for what remains); the model cannot widen the tool set (the manifest decides); results are data; any follow-up action is gated. The red-team suite carries both: `tool-description` and `mcp-result` carriers (cases in `evals/redteam/datasets/redteam-core.json`, category `indirect-injection`) and the Phase 4 e2e runs an in-repo server that returns an injection (`e2e/test_phase4_tools.py`, NEEDS #110: no third-party server was exercised).

## Tool misuse

`mcp-call` in the red-team pack is allowed only for server `corp-search` and tools `search` and `lookup`, with secret-shaped query text denied; other server names (`attacker-mcp`) and smuggled arguments (`server_override`) are blocked (cases `rt-ex-*` and `rt-tm-006`). In production the server/tool allowlist is enforced at spawn by the tenant registry before any policy runs.
