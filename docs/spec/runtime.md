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
  SigV4) and OpenAI-compatible endpoints; retries with jitter, per-provider circuit breaker, fallbacks, cost tables, prompt-cache
  hints. BYO keys via `SecretStore`; platform keys only when the tenant allows it. Secrets never appear in exceptions or logs.
- **Temporal** (`temporal.py`): each run is one `AgentRunWorkflow`. Workflow code is deterministic and holds no gate or backends;
  every action and log append is an activity. Activity results are the event-log entries.

## Concurrency between the workflow and in-flight activities

An activity appends events while it runs, so the workflow's recorder can be stale. `RunRecorder.record` catches a
`SequenceConflictError`, folds the events the other writer appended (`read_after`), re-validates and rebuilds the event on the new
head (bounded retries). It never overwrites or forks. A process killed while an action is in flight exits `killed`; the orphaned
activity may still complete its side effect (inherent to cancelling external work) and its later appends conflict harmlessly.

## What is tested how

| Area                                                                        | Evidence                                                                                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Process model, event log, replay, executor, gate client, redaction          | unit + property-style tests, mutation-checked (DENY performs, gate error/timeout to ALLOW, unspecified accepted)   |
| gRPC client                                                                 | in-process fake gRPC server (deadline, UNAVAILABLE, UNSPECIFIED). Against the real kernel: `e2e/` (Phase 2 exit)   |
| Temporal workflow                                                           | real Temporal time-skipping test server: end to end, deny, approval parking, signals/queries, timeout, lost activity result, bad manifest, and `Replayer` determinism check |
| Provider adapters                                                           | `httpx.MockTransport` fixtures written from provider docs. **No live provider calls have been made.**             |
| KMS secret store, S3/cloud sinks                                            | interfaces only (`docs/NEEDS.md`)                                                                                   |
| Bypass guard                                                                | `runtime/tests/test_bypass.py`: every `Action` type under a DENY gate has zero effects; AST test confines IO imports |

The Temporal test server binary is downloaded from the Java SDK's GitHub release (the SDK's default host is blocked in some
sandboxes); override with `AXIS_TEMPORAL_TEST_SERVER`. Tests fail, never skip, if it cannot be obtained.
