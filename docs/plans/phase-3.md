# Phase 3 plan — Orchestration and routing

Goal: multi-agent run with budgets enforced, NEXUS stage metrics visible in traces, approvals working end to end.

| #   | Component            | Location                                 | Coverage | Notes                                                                                           |
| --- | -------------------- | ---------------------------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| A   | TKI                  | `runtime/src/axis_runtime/tki/` (Python) | 95%      | scheduler, supervisor trees (one-for-one/all/rest), IPC mailboxes, budget ledger (tenant/agent/run), hard+soft caps, atomic reserve/commit |
| B   | NEXUS + MPM stub     | `runtime/src/axis_runtime/nexus/`        | 85%      | cache -> rules -> MPM -> RAG -> LLM; per-stage telemetry + cost attribution; MPM interface, registry, mock models, benchmark harness |
| C   | Approvals service    | `services/approvals` (TS)                | 95% (queue/SLA logic) | REQUIRE_APPROVAL queue, approver-role check, SLA timers, escalation chain, Slack/Teams/email adapters with fakes, audit of every transition, no self-approval |
| D   | Integration e2e      | `e2e/`                                   | -        | multi-agent run: parent spawns children, budget cap trips, NEXUS stage spans, approval granted/denied/expired flows |

## Rules
- Every action by any TKI-spawned agent still goes through the Risk Kernel gate (bypass test stays green and covers new code).
- Budget exhaustion is fail-closed (hard cap -> deny/stop); ledger writes are audited.
- Approvals: decision events are audit-appended; expiry => DENY (fail-closed); approver cannot be the requester.
- Status labels stay honest; in-memory stores recorded in docs/NEEDS.md.
