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
  `*.localdomain` are rejected; malformed DNS names (empty or over-long label, name over 253 bytes) are rejected before any
  lookup; the hostname is resolved and **every** returned address must be public. Special-purpose space is denied explicitly
  even where Python's `ipaddress.is_global` says otherwise (`fec0::/10`, `2001:db8::/32`, `3fff::/20`, `100::/64`,
  `64:ff9b:1::/48`, `192.0.0.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, ...). **Any** resolver exception
  (including the `UnicodeError` the default resolver raises for bad IDNA labels) becomes an `EndpointError`, surfaced by the
  gateway as a non-retryable `ModelError` (`INVALID_REQUEST`, the kind used for every endpoint rejection).
- The resolver is injectable (`ModelGateway(resolver=...)`; default: the event loop's `getaddrinfo`, built lazily, never at
  import) and lives in `models/adapters/base.py`, the only file that imports `socket`.
- `TenantModelPolicy.allow_private_endpoints` (default `False`) skips the host/address checks for self-hosted deployments
  (scheme and userinfo are still enforced).
- **Known gap: DNS rebinding.** The address that passed the check is not pinned for the connection; `httpx` resolves the name
  again at connect time, so a hostile resolver can answer differently the second time. Connect-time pinning (a transport that
  connects to the validated IP with the original Host/SNI) is **not implemented** (`docs/NEEDS.md` row 22). Redirects are not
  followed by the transport by default, which limits but does not remove the exposure.
- Circuit breakers are keyed by `(tenant_id, provider, endpoint)`, so one tenant's failing endpoint cannot open the circuit for
  another tenant or for the same tenant's other endpoints. The map is a bounded LRU (`max_breakers`, default 1024): the least
  recently used **closed** breaker is evicted first; open/half-open breakers are never evicted (so eviction cannot reset a tripped
  circuit), and when every slot is tripped a new endpoint is refused with a non-retryable `CONFIGURATION` error. State is still
  per process (`docs/NEEDS.md` row 24).

## Bypass guard: design and limits

Goal: no code path may perform a tool, MCP, model, memory, message, code or browser action without the gate decision.
Three independent layers; none of them is a sandbox.

1. **Runtime tripwires** (`guard.py`): `Action.perform` needs the executor's token; `ModelGateway.complete/stream` need
   `in_executor()`. They stop accidents, not a caller who can run arbitrary code in the process.
2. **Static allowlist scan** (`runtime/tests/bypass_scan.py`, run by `test_bypass.py` over all of `src/axis_runtime`, generated
   `_gen/` excluded):
   - _Imports are allowlisted._ A module may import only `SAFE_IMPORTS` (stdlib modules whose own API has no process/network/file-write capability, see the caveat below; `axis_runtime`, protobuf JSON/Struct,
     `cryptography.fernet`; one comment per entry) unless its file has an `IO_IMPORTS` grant for that module with a reason
     (`httpx`: transport and MCP client; `socket`: the DNS resolver; `grpc`: gate client; `temporalio`: workflow wiring; `os` /
     `pathlib`: the dev secret file and process-model lookup). Anything unknown, including modules nobody thought of, fails.
   - _Constructs are banned by AST_ outside per-rule file exemptions: `eval`/`exec`/`compile`/`__import__`/`globals`/`vars`,
     `getattr`/`setattr`/`delattr` with a non-literal name, introspection (`__dict__`, `__globals__`, `__subclasses__`, frames,
     `import_module`), `sys.modules`, process creation (`os.system/popen/exec*/spawn*/fork*`, `create_subprocess_*`), network
     primitives (`open_connection`, `start_server`, `create_connection`, ...), name resolution, file writes/removals
     (`os.remove/rename/...`, `Path.write_text/touch/unlink/...`, `shutil`), `open()`/`Path.open()` with a write mode (mode
     read from the keyword and from both positional slots; dynamic modes count as writes), logging file/socket sinks, `ctypes`,
     `pickle`, `marshal`. Import aliases are resolved (`import os as o; o.system(...)`).
   - _"Safe" does not mean pure compute._ `logging`, `asyncio`, `contextlib`, `typing`, `random` and `inspect` import and
     therefore re-export `os`, `sys`, `subprocess`, `socket`, `threading`, `io`, ... (`logging.os.system`, `typing.sys.modules`,
     `asyncio.subprocess.subprocess.Popen`, `random._os.system`). Two rules cover this: **transitive-module** flags any attribute
     segment (or `from safe import name`) naming a dangerous module (`os sys subprocess socket threading io builtins _os _socket
_io posix nt ctypes importlib pickle marshal shutil tempfile signal _thread multiprocessing concurrent`), whatever the base
     expression is (so `inspect.getmodule(x).os` is caught); **unlisted-member** confines `asyncio`, `logging`, `inspect`,
     `contextlib` and `random` to the members `src` actually uses (`MEMBER_ALLOW`), and denies a few `typing` re-exports.
     Also banned: `logging.basicConfig/fileConfig/dictConfig/FileIO` and file handlers, loop socket methods (`sock_sendall`,
     `sock_recv`, `sendfile`, ...), thread hops (`run_in_executor`, `to_thread`), `eval/exec/__import__/globals/locals/vars`
     and non-`re` `.compile` as **attributes** (`builtins.exec`, `x.eval`), and string constants used as attribute names
     (`getattr(f, "__globals__")`, `attrgetter("a.__class__.__mro__")`, `x["__builtins__"]`) are checked against the
     introspection/dangerous-module sets.
   - _Executor-only names_ (`_TOKEN`, `executing`, `in_executor`, `call_tool`, `perform`, `ToolRegistry.call`,
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
   _What it proves:_ no forbidden IO happens when a gate **denies**, requires approval, or is unavailable, for every action type.
   It does **not** claim an **allowed** action is IO-free: allowed actions are expected to do IO, and the ALLOW scenario uses
   the scripted transport only so the suite needs no network, so an IO event on the allow path is not a bypass. A bypass is IO
   that happens without a gate consult. To back that up the recorder notes whether `guard.in_executor()` (the executing
   context, set only while the executor performs an allowed action) was active for each event; a test with a tool that really
   writes a file asserts every such event is inside it, and that the same write outside the executor is recorded as outside.
   (The executing context is itself a forgeable contextvar, so this is a consistency check, not proof.)

**What this does not prove.** Static analysis cannot show the absence of a bypass: string-built attribute access through a
construct the scanner does not model, code loaded from data, a dependency that performs IO internally (an allowlisted library
such as `httpx` or `temporalio` is trusted wholesale), C extensions, or a future allowlist entry that is granted carelessly all
evade it. Concretely the scanner still cannot catch: aliasing a module through a value the scanner does not track and then
reaching a dangerous member whose name is not in its sets (e.g. `x = some_obj; x.any_method_that_does_io()`), dangerous members
of modules it trusts wholesale (`json`, `re`, `hashlib`, `cryptography.fernet`, protobuf, the `IO_IMPORTS` grants), attribute
names built at runtime that are never passed to `getattr`-family calls as literals (those with non-literal names are banned
outright, but `operator`-style lookups through unmodelled helpers are not), behaviour added by `typing` members beyond the
small denylist, and anything done by C extensions or by data that becomes code. The audit-hook check only covers the scenarios
it runs. The real boundary is process isolation and network egress
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
| Bypass guard                                                       | `test_bypass.py` + `bypass_scan.py` (allowlist AST scan, probe corpus), `test_audit_hook.py` (audit events), every `Action` type under a DENY gate has zero effects         |
| Endpoint SSRF checks, per-tenant breakers                          | `runtime/tests/test_endpoints.py`: fake resolver, IP/host/port corpus, platform-key refusal, breaker isolation                                                              |

The Temporal test server binary is downloaded from the Java SDK's GitHub release (the SDK's default host is blocked in some
sandboxes); override with `AXIS_TEMPORAL_TEST_SERVER`. Tests fail, never skip, if it cannot be obtained.
