# ADR 0011: TKI design (scheduler, supervisors, IPC, budget ledger)

Status: accepted · Phase 3 component A · Contracts unchanged (no freeze-manifest change)

## Context

Phase 3 needs multi-agent runs with enforced budgets. `run.py` already has a per-run `AgentProcess` with one-for-one child
restarts and per-process budget checks computed from the event log (after the fact). We need tenant-aware scheduling, the three
supervision strategies, mailboxes, and budgets that are checked **before** spend and shared up a tree, without a new path
around the Risk Kernel.

## Decisions

1. **TKI wraps, it does not replace, the executor.** `agent_workload` runs `start_agent`; `BudgetedRunner` wraps the single
   `ActionExecutor` via the existing `RunDeps.runner_factory` seam. It adds reserve-before-spend and commit/release around the
   executor call and can only refuse. `run.py`/`executor.py` are untouched. The scheduler runs opaque workloads and performs no
   actions, so the bypass scanner needs only two allowlist changes (read access to the IPC schema file for `tki/ipc.py`; no new
   safe imports).
2. **Ledger operations are synchronous.** Atomicity under asyncio comes from having no `await` inside reserve/commit/release;
   no locks. The `BudgetLedger` protocol is the seam for a Redis/Postgres implementation later (NEEDS #41), which will need real
   atomic scripts/transactions.
3. **Commit clamps, never exceeds.** Actual spend can exceed the reservation (token counts are only known after a model call).
   Rather than allow `committed > hard` or reject a spend that already happened, the excess beyond remaining headroom is clamped,
   reported as `overrun`, emitted as `budget_hard_cap`, and terminates the process. Invariant `committed <= hard` always holds.
4. **Hard-cap trip terminates the spender (and its subtree) with `budget_exceeded`.** Not the whole account's subtree: siblings
   fail on their own next reserve.
5. **Restart eligibility is a closed list** (`failed`, `timeout`, and `completed` under `always`). `budget_exceeded`,
   `policy_denied`, `killed`, `parent_terminated` are never restarted: a supervisor must not undo a cap, a denial or a kill switch.
6. **Accounts hang under the parent process for children** and under tenant/agent/run for roots; the agent scope is the root agent.
   This makes "child spend counts against parent and tenant" structural rather than a separate roll-up step.
7. **Audit before apply** for every state change through an injected `EventSink`; a failing sink blocks the change (fail-closed).
8. **Cancellation is cooperative with escalation**, and the first termination decision wins so a workload cannot mask a kill or
   trip by returning normally. The running task is never cancelled from inside itself (Python 3.12 `uncancel` does not clear a
   pending cancel); the cancel is delivered on the next loop step.
9. **Fairness = round-robin across tenants within a priority level, plus aging**, chosen over weighted fair queuing for
   auditability; per-tenant concurrency limits are separate from queue order.

## Consequences

- State (queue, mailboxes, ledger, process table) is in memory and single-instance. Durable, distributed variants are future
  work (NEEDS #41-#43).
- `run.py`'s in-run `spawn_child` is not (yet) routed through a TKI `Supervisor` (NEEDS #45).
