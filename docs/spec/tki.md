# TKI — the AXIS process kernel

Status: **Built (single instance, in-memory state)** · Code: `runtime/src/axis_runtime/tki/` · Tests: `runtime/tests/test_tki_*.py`
· Decision record: `docs/adr/0011-tki-design.md` · Gaps: `docs/NEEDS.md` #55-#61

TKI schedules, supervises, connects and meters agent processes. It sits **below** nothing and **beside** the gate: it never
performs an action. A TKI-supervised agent still acts only through `ActionExecutor` and the Risk Kernel gate (`adapter.py`
wraps that same executor; it cannot route around it). The process states, transitions, signals and exit reasons are the frozen
`process-model.json`; the IPC envelope is the frozen `ipc-envelope-v1` schema. TKI adds no contract.

## Modules

| Module          | Responsibility                                                                         |
| --------------- | -------------------------------------------------------------------------------------- |
| `events.py`     | `TkiEvent`, `EventSink` (injected, may raise), `ListSink`                              |
| `budget.py`     | hierarchical budget ledger (`BudgetLedger` protocol, `InMemoryLedger`)                 |
| `ipc.py`        | `Envelope`, bounded `Mailbox`, tenant-isolated `MessageRouter`                         |
| `scheduler.py`  | priority + fair queue, concurrency limits, signals, cascade, `ProcessContext`          |
| `supervisor.py` | supervisor trees: strategies, restart policy and intensity, `limits_from_manifest`     |
| `adapter.py`    | `agent_workload` + `BudgetedRunner`: run a real agent under TKI, budgeted, still gated |

## Scheduler

A process holds a **slot** only while `running`. All `ready` processes wait in one queue. On every slot release the dispatcher
picks the entry minimising `(effective_priority, tenant_last_served, enqueue_seq)`:

- `Priority.HIGH=0 < NORMAL=1 < LOW=2` (any int >= 0). **Aging:** every `aging_interval` dispatches an entry has waited improves
  its effective priority one level, so low-priority work cannot starve.
- **Fairness:** among equal priority the tenant served least recently goes first, so a tenant flooding the queue cannot push
  another tenant's work behind its own.
- **Limits:** `max_running` globally and a per-tenant limit (`default_tenant_limit`, overridable per tenant). A tenant at its
  limit is skipped, never head-of-line blocking others.
- A workload yields cooperatively: `ctx.yield_()` (running -> ready -> queued again), `async with ctx.waiting():` (running ->
  waiting, slot released, `wake` re-queues), `ctx.checkpoint()` (cancellation + PAUSE safe point).

Every transition goes through `process.next_state` and is emitted to the sink **before** it is applied (`process_transition`,
same shape as the run log: `from/to/trigger/exit_reason/detail`).

### Signals and cancellation

| Signal      | Effect                                                                                                                                                                                             |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TERM`      | cooperative: sets the `CancelToken`; the workload sees it at `checkpoint()`. Escalates to KILL after `term_grace_seconds`. Immediate if the process is not running. Exit `killed`, trigger `TERM`. |
| `KILL`      | immediate task cancellation, exit `killed`, trigger `KILL`                                                                                                                                         |
| `PAUSE`     | ready: suspended at once; running: at the next `checkpoint()`; waiting: after wake                                                                                                                 |
| `RESUME`    | suspended -> ready -> queued                                                                                                                                                                       |
| `INTERRUPT` | queued for `ctx.take_interrupts()`, no state change                                                                                                                                                |

The first termination decision wins (`proc.outcome`); a workload that returns `completed` or swallows an exception cannot mask a
kill, a budget trip or a timeout. After a cancel the context refuses all spend and messaging (`ProcessCancelled`).

### Trees

`SpawnSpec.ppid` makes a child. Same-tenant only (an unknown and a cross-tenant parent are reported identically). Terminating any
process first terminates its live children: `TERM` then `KILL` signal events, exit `parent_terminated`, no grace, children
before the parent's own `terminated` event. A child that ignores cancellation is force-recorded as terminated after
`child_kill_wait_seconds` (its task cannot be killed by Python; see NEEDS #59).

## Supervisors

`Supervisor(scheduler, parent_pid, SupervisorConfig)`; children are `ChildSpec`s (`ChildSpec.from_manifest` reads the child's
`restart_policy`/`max_restarts`/budgets; `SupervisorConfig.from_process_config` reads `supervisor`/`max_children`).

- **Strategies.** `one-for-one` restarts the failed child. `one-for-all` terminates every live sibling (exit `killed`, detail
  `supervisor one-for-all`) then restarts all in start order. `rest-for-one` does the same for the failed child and those
  started after it. Siblings that already terminated are not resurrected.
- **Restart policy.** `never`; `on-failure` restarts `failed` and `timeout`; `always` also restarts `completed`.
- **Never restarted, whatever the policy:** `budget_exceeded`, `policy_denied`, `killed`, `parent_terminated`. A restart must not
  be a way around a cap, a denial or a kill switch.
- **Intensity.** A child is restarted at most `max_restarts` times within `window_seconds` (sliding; `None` = lifetime).
  Optional `max_total_restarts` bounds the whole supervisor; exceeding it terminates every child and emits
  `supervisor_escalated`. Exceeding a per-child budget leaves that child down and emits `supervisor_escalated`.
- **Limits.** `max_children` bounds _live_ children (restarts replace, they do not add).
- A restarted child is a **new process** (new PID, new account under the same parent), so ledger totals keep counting.

## IPC

`Envelope` mirrors `ipc-envelope-v1` (its patterns are read from the schema file, not copied; a drift guard fails import).
`MessageRouter.send` checks, in order: sender registered **in the envelope's tenant** -> `authorize` hook (required argument;
`False`, non-`True` or an exception denies) -> recipient resolved **inside that tenant** -> audit event `ipc_sent` -> delivery.
Unknown and cross-tenant recipients are indistinguishable (`recipient unavailable`). If the sink raises, nothing is delivered.
Mailboxes are bounded (back-pressure: `MailboxFullError`); channel fan-out skips full subscribers and lists them in the audit
event; TTL-expired messages are dropped on receive with `ipc_dropped`. Channels are keyed `(tenant, name)`.

The router is the **delivery layer**. Production wiring must pass an `authorize` that asks the Risk Kernel (a `MessageSend`-style
action through the executor). Agent-facing IPC tools are not built (NEEDS #58).

## Budget ledger

Accounts: `tenant -> agent -> run -> process -> child process`. Resources (integers only): `tokens`, `cost_micro_usd`,
`runtime_ms`, `tool_calls`. A `Limit` has optional `soft` and `hard`.

- `reserve(key, amounts)` checks the leaf and **every ancestor**; if any hard cap would be exceeded it raises
  `BudgetExceededError` and changes nothing. `commit(res, actual)` settles up to the reservation plus remaining headroom;
  anything beyond the hard cap is **clamped and reported** as `overrun` (so `committed <= hard` always). `release` returns the
  reservation. A reservation settles exactly once. All three are synchronous (no `await`), hence atomic under asyncio.
- **Soft cap:** one `budget_soft_cap` event the first time `committed` reaches it.
- **Hard cap:** `budget_denied` (refused reserve) or `budget_hard_cap` (clamped commit); the scheduler turns either into
  termination of the spending process with `ExitReason.BUDGET_EXCEEDED` (children cascade), even if the workload swallows the
  error.
- **Audit:** every reserve/commit/release/denial is emitted before it is applied; a failing sink leaves the ledger unchanged
  (release is applied first so cleanup never leaks funds).
- **Runtime budget** is enforced by a watchdog armed from the chain's remaining `runtime_ms` headroom at first run, and charged
  (clamped) on exit. It is not reserve-before-spend (NEEDS #60). `timeout_seconds` is a separate watchdog (`timeout`).
- **Scopes.** A root process hangs under tenant -> agent -> run; a child hangs under its parent's process account, so a child
  of another agent still counts against the run and the parent. The agent scope is the _root_ agent of the run.

Property tests (seeded random + concurrent asyncio tasks) assert: `committed + reserved <= hard` at every account at every
step, never negative, committed totals conserved up the tree, no oversubscription under overlapping reservations.

## What is not proven or built

See NEEDS #55-#61: in-memory single-instance ledger/queue/router, no durable or distributed budgets, agent-initiated IPC not
exposed, in-run `spawn_child` (run.py) not yet supervised by TKI, cost not reserved before spend without an estimator.
