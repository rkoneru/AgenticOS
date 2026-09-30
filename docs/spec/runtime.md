# Agent runtime (Python)

Status: **Built (Phase 2)**, integration-tested against a real Temporal test server; provider adapters are fixture-tested only.
Code: `runtime/src/axis_runtime`. Decisions: ADR-0009.

## Shape

```
RuntimeManifest ─▶ AgentProcess (spawn→ready→running→waiting→suspended→terminated)
                        │ every external action
                        ▼
                  ActionExecutor ──▶ GateClient (gRPC to the Risk Kernel, fail-closed)
                        │ ALLOW / ALLOW_WITH_REDACTION only
                        ▼
                  Action.perform (guarded by a capability token only the executor holds)
                        │
                        ▼
                  RunRecorder ──▶ RunEventLog (append-only, hash-chained, gapless per run)
```

- **Process model** (`process.py`) is loaded from `packages/contracts/process-model.json`; transitions, signals and PIDs are not
  duplicated in Python.
- **Event sourcing** (`events.py`): run state is only ever `reduce(events)`. Events are validated against the folded state
  _before_ they are appended, so an illegal event never reaches the log. `replay(log)` rebuilds the full state.
- **Fail-closed gate client** (`gate.py`): exception, timeout, malformed response or `DECISION_UNSPECIFIED` is `DENY`.
- **Executor** (`executor.py`, `actions.py`): tool, MCP, model, memory, message, code and browser actions are `Action`
  subclasses. `Action.perform` refuses to run without the executor's capability token. `REQUIRE_APPROVAL` returns
  `PendingApproval` and performs nothing; `ALLOW_WITH_REDACTION` redacts arguments and results by field path.
- **ModelGateway** (`models/`): provider-neutral. Adapters for Anthropic, OpenAI, Google, Azure OpenAI, Bedrock (hand-written
  SigV4) and OpenAI-compatible endpoints; retries with jitter, circuit breakers keyed by (tenant, provider, endpoint), fallbacks, cost tables, prompt-cache
  hints. BYO keys via `SecretStore`; platform keys only when the tenant allows it, and never together with an ABL endpoint override. Secrets never appear in
  exceptions or logs.
- **Temporal** (`temporal.py`): each run is one `AgentRunWorkflow`. Workflow code is deterministic and holds no gate or backends;
  every action and log append is an activity. Activity results are the event-log entries.

## ModelGateway endpoint safety

ABL may set `target.endpoint` (required for `openai-compatible` and `azure-openai`). It is attacker-influenced input, so:

- **Platform keys never go to a custom endpoint.** If the tenant has no key of its own, the platform key would be used, and an
  endpoint override is present, the call fails with a non-retryable `ErrorKind.CONFIGURATION`. An endpoint may only be combined
  with the tenant's own BYO key.
- **Validation** (`models/endpoints.py`, run before any key is read or request sent): https only (http only if the gateway was
  built with `allow_http_endpoints`); no userinfo; port 443 unless listed in `extra_endpoint_ports`; IP literals must be public
  (IPv4 and IPv6, including IPv4-mapped, 6to4, NAT64 and Teredo forms); numeric-looking hosts (`2130706433`, `0x7f.0.0.1`,
  `0177.0.0.1`, `127.1`) are rejected; `localhost`, `*.localhost`, `*.internal` (covers `metadata.google.internal`), `*.local`,
  `*.localdomain` are rejected; the hostname is resolved and **every** returned address must be public.
- The resolver is injectable (`ModelGateway(resolver=...)`; default: the event loop's `getaddrinfo`, built lazily, never at
  import) and lives in `models/adapters/base.py`, the only file that imports `socket`.
- `TenantModelPolicy.allow_private_endpoints` (default `False`) skips the host/address checks for self-hosted deployments
  (scheme and userinfo are still enforced).
- **Known gap: DNS rebinding.** The address that passed the check is not pinned for the connection; `httpx` resolves the name
  again at connect time, so a hostile resolver can answer differently the second time. Connect-time pinning (a transport that
  connects to the validated IP with the original Host/SNI) is **not implemented** (`docs/NEEDS.md` row 18). Redirects are not
  followed by the transport by default, which limits but does not remove the exposure.
- Circuit breakers are keyed by `(tenant_id, provider, endpoint)`, so one tenant's failing endpoint cannot open the circuit for
  another tenant or for the same tenant's other endpoints. The breaker map is unbounded in (tenant x endpoint) cardinality
  (in-process, fine at current scale; `docs/NEEDS.md` row 20).

## Bypass guard: design and limits

Goal: no code path may perform a tool, MCP, model, memory, message, code or browser action without the gate decision.
Three independent layers; none of them is a sandbox.

1. **Runtime tripwires** (`guard.py`): `Action.perform` needs the executor's token; `ModelGateway.complete/stream` need
   `in_executor()`. They stop accidents, not a caller who can run arbitrary code in the process.
2. **Static allowlist scan** (`runtime/tests/bypass_scan.py`, run by `test_bypass.py` over all of `src/axis_runtime`, generated
   `_gen/` excluded):
   - *Imports are allowlisted.* A module may import only `SAFE_IMPORTS` (pure-compute stdlib, `axis_runtime`, protobuf JSON/Struct,
     `cryptography.fernet`; one comment per entry) unless its file has an `IO_IMPORTS` grant for that module with a reason
     (`httpx`: transport and MCP client; `socket`: the DNS resolver; `grpc`: gate client; `temporalio`: workflow wiring; `os` /
     `pathlib`: the dev secret file and process-model lookup). Anything unknown, including modules nobody thought of, fails.
   - *Constructs are banned by AST* outside per-rule file exemptions: `eval`/`exec`/`compile`/`__import__`/`globals`/`vars`,
     `getattr`/`setattr`/`delattr` with a non-literal name, introspection (`__dict__`, `__globals__`, `__subclasses__`, frames,
     `import_module`), `sys.modules`, process creation (`os.system/popen/exec*/spawn*/fork*`, `create_subprocess_*`), network
     primitives (`open_connection`, `start_server`, `create_connection`, ...), name resolution, file writes/removals
     (`os.remove/rename/...`, `Path.write_text/touch/unlink/...`, `shutil`), `open()`/`Path.open()` with a write mode (mode
     read from the keyword and from both positional slots; dynamic modes count as writes), logging file/socket sinks, `ctypes`,
     `pickle`, `marshal`. Import aliases are resolved (`import os as o; o.system(...)`).
   - *Executor-only names* (`_TOKEN`, `executing`, `in_executor`, `call_tool`, `perform`, `ToolRegistry.call`,
     `ModelGateway.complete/stream`, constructing `ModelGateway`, `Backends.need`, the token helpers) may appear only in the files
     that own them, as identifiers, attributes, definitions, imports **and exact string constants** (so `getattr(x, "perform")`
     is caught; dynamic names are already banned).
   - The scanner is itself tested: a probe corpus containing every bypass a reviewer demonstrated against the earlier denylist
     (`os.system`, `urllib` via bare `import urllib`, `ctypes`, `pickle`, `with guard.executing(): gateway.complete(...)`, ...)
     must be flagged, negative controls must not be, and stale allowlist entries fail the suite.
3. **Dynamic audit-hook check** (`test_audit_hook.py`): one `sys.addaudithook` recorder (installed once, inert outside its
   `recording()` window because hooks cannot be removed) records `socket.connect/bind/getaddrinfo`, `subprocess.Popen`,
   `os.system`, `os.exec*`, `os.posix_spawn`, `ctypes.*`, `shutil.*`, removals and `open` for writing. Every action type under a
   DENY gate, approval-pending, gate outage, and a scripted ALLOW run must record none. A non-vacuity test performs each
   operation for real and requires the recorder to see it.

**What this does not prove.** Static analysis cannot show the absence of a bypass: string-built attribute access through a
construct the scanner does not model, code loaded from data, a dependency that performs IO internally (an allowlisted library
such as `httpx` or `temporalio` is trusted wholesale), C extensions, or a future allowlist entry that is granted carelessly all
evade it. The audit-hook check only covers the scenarios it runs. The real boundary is process isolation and network egress
policy around the runtime (Phase 3+ sandboxes); this test suite is a regression net, not a security boundary.

## Concurrency between the workflow and in-flight activities

An activity appends events while it runs, so the workflow's recorder can be stale. `RunRecorder.record` catches a
`SequenceConflictError`, folds the events the other writer appended (`read_after`), re-validates and rebuilds the event on the new
head (bounded retries). It never overwrites or forks. A process killed while an action is in flight exits `killed`; the orphaned
activity may still complete its side effect (inherent to cancelling external work) and its later appends conflict harmlessly.

## What is tested how

| Area                                                               | Evidence                                                                                                                                                                    |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Process model, event log, replay, executor, gate client, redaction | unit + property-style tests, mutation-checked (DENY performs, gate error/timeout to ALLOW, unspecified accepted)                                                            |
| gRPC client                                                        | in-process fake gRPC server (deadline, UNAVAILABLE, UNSPECIFIED). Against the real kernel: `e2e/` (Phase 2 exit)                                                            |
| Temporal workflow                                                  | real Temporal time-skipping test server: end to end, deny, approval parking, signals/queries, timeout, lost activity result, bad manifest, and `Replayer` determinism check |
| Provider adapters                                                  | `httpx.MockTransport` fixtures written from provider docs. **No live provider calls have been made.**                                                                       |
| KMS secret store, S3/cloud sinks                                   | interfaces only (`docs/NEEDS.md`)                                                                                                                                           |
| Bypass guard                                                       | `test_bypass.py` + `bypass_scan.py` (allowlist AST scan, probe corpus), `test_audit_hook.py` (audit events), every `Action` type under a DENY gate has zero effects        |
| Endpoint SSRF checks, per-tenant breakers                          | `runtime/tests/test_endpoints.py`: fake resolver, IP/host/port corpus, platform-key refusal, breaker isolation                                                              |

The Temporal test server binary is downloaded from the Java SDK's GitHub release (the SDK's default host is blocked in some
sandboxes); override with `AXIS_TEMPORAL_TEST_SERVER`. Tests fail, never skip, if it cannot be obtained.
