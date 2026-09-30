# Process model

Status: **Frozen (v1)** · Source of truth: `packages/contracts/process-model.json` (+ `schemas/ipc-envelope-v1.schema.json`)

Agents are OS-style processes.

```
spawn ──init_complete──▶ ready ◀──yield── running ──await──▶ waiting
  │                        │  └──scheduled──▶ │ ◀──wake─────────┘
  └─init_failed─┐          └────────┬─────────┘
                ▼                   ▼ PAUSE (from ready/running/waiting)
            terminated ◀──exit── (running)      suspended ──RESUME──▶ ready
                ▲ KILL / TERM from any non-terminal state
```

- **States:** `spawn → ready → running → waiting → suspended → terminated`. `terminated` is absorbing.
- **Signals:** `PAUSE`, `RESUME`, `TERM` (graceful, escalates to KILL after the grace period), `KILL` (immediate; also how
  kill-switches act), `INTERRUPT` (out-of-band message, no state change).
- **Exit reasons:** `completed, failed, killed, budget_exceeded, policy_denied, timeout, parent_terminated`. The DB enforces
  `state = terminated ⇔ exit_reason is set`.
- **PIDs:** `axp_` + 26-char ULID (Crockford base32): time-sortable, globally unique, not secret. Every row and message also
  carries `tenant_id`; isolation never relies on PID secrecy. `ppid` is stored separately; a run's init process has null `ppid`.
- **Trees:** terminating a parent sends TERM then KILL to children (`parent_terminated`). Supervision strategies come from ABL
  `spec.process.supervisor`.
- **Durability:** every transition is an append-only `run_events` row (event-sourced, replayable) and an audit event
  (`enforcement_point: lifecycle`).
- **IPC envelope:** `{schema_version, id, tenant_id, trace_id, from, to, kind, correlation_id?, ts, ttl_seconds?, payload}`;
  `to` is a PID or `chan:<name>` (tenant-scoped pub/sub); `kind` ∈ message, event, request, response (responses require
  `correlation_id`). Every IPC send passes the gate like any other action.
