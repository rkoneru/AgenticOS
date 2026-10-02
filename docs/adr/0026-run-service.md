# 0026. Dev run service (`runtime/src/axis_runtime/runserver.py`)

Status: Accepted · Date: 2026-10-02 · Related: 0012, 0017, 0022, 0024

## Context

The gateway starts, signals and reads runs. The Python runtime has `start_agent`/`run_agent` and event-sourced run state but no
network surface, and Temporal is only proven on the time-skipping test server.

## Decision

A DEV, NON-PRODUCTION asyncio/stdlib HTTP server in the runtime package, called only by the gateway:

- Bearer authentication from a `token -> tenant` table (constant-time compare); the tenant is the token's, never the request's.
  A run id owned by another tenant is `404`, exactly like an unknown id.
- `POST /v1/runs` takes `{run_id, trace_id, blueprint, manifest, input, principal}`: the gateway compiles the ABL with the TS
  compiler and sends the RuntimeManifest, so the runtime never parses ABL. The server builds `RunDeps` per tenant through an injected
  `DepsFactory` (the production-shaped factory wires the kernel gate over gRPC, the control-plane bridge for the BYO key and budgets,
  TKI with the tenant's budgets, NEXUS, memory/tools as configured, and the usage emitter; tests inject scripted fakes).
- Run state is the fold of the event log (`events.reduce`), exposed as the OpenAPI `Run`; the log is an `InMemoryRunEventLog` behind
  the `RunEventLog` port (hash-chained, gapless). A Postgres-backed log is NOT built (NEEDS #224): `run_events` has no hash columns
  and the runtime has no Postgres driver, so it needs a migration, an ADR and a driver choice of its own.
- Signals go through the TKI scheduler (`Scheduler.signal`) so budgets, suspension and parent-terminates-child semantics are the ones
  already tested; `GET .../events` and an SSE feed (`.../events/stream`) serve the log; `POST .../replay` re-folds the log and
  verifies the hash chain.
- `bypass_scan` gets ONE scoped exemption (`net` rule, `.start_server`, file `runserver.py`) mirroring `mcp/http_server.py`; the
  process launcher lives outside the scanned package (`runtime/scripts/run_server.py`).

## Consequences

Runs are lost on restart (in-memory log); a durable log, Temporal-hosted runs and a worker pool are Phase 10 work. Every action of
every run still passes the kernel gate through `RunDeps.gate`; the server has no code path that performs an action itself.
