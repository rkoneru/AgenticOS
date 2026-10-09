# 0101. Chaos suite, fail-closed assertions, and persistent kill-switches

Status: Accepted · Date: 2026-10-09 · Related: 0100, 0102

## Context

Phase 9 requires evidence that faults never turn into allowed actions. The suite (`chaos/`, `make chaos`) runs on the real stack with an in-repo TCP fault
proxy and process kill/restart. Its design review and first runs found fail-OPEN and availability defects.

## Decision

1. **Kill-switches survive a kernel restart.** `MemoryKillSwitchStore` forgot every engaged switch on restart: a crash or deploy released a tenant's kill-switch
   (fail-open). `FileKillSwitchStore` (`AXIS_RK_KILL_STATE_FILE`) persists them: ENGAGE applies in memory first and is persisted best-effort; RELEASE is persisted
   first and, if that fails, the switch stays engaged and the call fails; a corrupt state file REFUSES to start the kernel. Single instance only; Redis with cross-instance
   propagation (< 1 s) remains the production design (NEEDS 3403).
2. **Idle Postgres connection errors must not crash a service.** `pg.Pool` emits `error` for a dropped idle client; unhandled it killed the gateway (found by chaos test 06).
   Every service `main.ts` now handles it; the next use reconnects and requests meanwhile fail closed (503 / DENY).
3. **Control plane down**: runs do not start (budgets and BYO key unavailable); the kernel keeps enforcing the last activated policy bundle from its own store; a tenant
   with no activated policy is DENIED. Asserted in test 08.
4. **No retry-masking**: chaos tests have no retries; faults are applied through the proxy/process control and observed through the API.

## Consequences

Recorded, not fixed (fail-closed but a gap): pending approvals, rate-limit/budget counters and in-flight run state live in process memory and are lost on restart (NEEDS 3404-3406).
The proxy itself had a byte-reordering bug under trickle+jitter that corrupted HTTP/2; fixed with per-direction ordered release and tested.
