# Runbook: chaos suite (`make chaos`)

Phase 9 D. Breaks one dependency of the REAL stack at a time and asserts the system FAILS CLOSED and recovers.

```bash
make chaos     # ~2 minutes: pytest chaos/ (18 tests on the real stack) + pnpm --filter @axis/chaos test (proxy + clock-skew unit tests)
```

## Tools

- `chaos/src/proxy.ts`: an in-repo TCP fault-injection proxy (the equivalent of Toxiproxy): `down` (RST), `blackhole` (partition without RST),
  `latency` + jitter, `trickle` (slow-loris on responses), `resetAfterBytes` (cut mid-response), bandwidth cap. Byte order per direction is
  preserved (a reordering bug in the first version corrupted HTTP/2 and was found by the suite). `chaos/src/cli.ts` runs one with an HTTP control port.
- `e2e/interfaces_stack.py` has `hop` (a proxy on the kernel, kernel-DB, gateway-DB, control-plane and run-service edges), `kill` and `restart`
  (same port, same environment). The kernel, run service and gateway therefore keep their addresses across a restart.

## What is asserted

| #    | Fault                                                                        | Fail-closed assertion                                                                                       | Recovery assertion                                    |
| ---- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 01   | kernel killed before a run                                                   | run STOPS, no model call or tool ran, every decision DENY with a `gate_` reason                             | kernel restarted: next run performs, no other restart |
| 02   | kernel killed while a payout awaits approval                                 | payout never runs, no ALLOW row for it                                                                      | -                                                     |
| 03   | kernel restarted with a tenant kill-switch engaged                           | switch STILL engaged (fixed: it used to be released)                                                        | release works                                         |
| 04   | kill-switch state unwritable (disk full / read-only)                         | engage works, release is refused (500) and the switch stays engaged                                         | -                                                     |
| 05   | kernel loses its audit database                                              | decisions DENY, no ALLOWed model/tool decision exists, chain still verifies                                 | pool reconnects without restart                       |
| 06   | gateway loses its database                                                   | `POST /runs` and `GET /me` answer 503, no run created                                                       | resumes without restart (fixed: it used to crash)     |
| 07   | Postgres failover (resets + window with nothing listening)                   | answered 503 within 20 s, not hung                                                                          | no restart needed                                     |
| 08   | control plane down                                                           | run does not start (502/503); a tenant with NO activated policy is denied everything                        | resumes                                               |
| 09   | run service SIGKILLed mid-run                                                | clean 404/502/503, no duplicate or unapproved side effect even if the approval is granted after the restart | new runs work                                         |
| 10   | gateway cannot reach the run service                                         | 502/503/504 for runs; `/me` and audit reads unaffected                                                      | resumes                                               |
| 11   | slow (7 s round trip), silent (blackhole) and trickled gate                  | `gate_timeout` DENY, nothing ran, run ends in under 60 s                                                    | next run performs                                     |
| 12   | connection cut mid-response                                                  | DENY, nothing ran                                                                                           | -                                                     |
| 13   | 30 MB body, 200k-deep JSON, 100 KB header                                    | 413 / 400 / 431 or connection closed; gateway still healthy                                                 | -                                                     |
| 14   | 1500 half-open connections (slow-loris)                                      | a real client is still served in under 10 s                                                                 | -                                                     |
| 15   | 200 KB tool argument                                                         | run terminates, no crash                                                                                    | -                                                     |
| unit | clock skew (approvals freshness, billing future events and seal closability) | a skewed clock only ever REFUSES                                                                            | -                                                     |

## Chosen behaviour when the control plane is down

A run needs the tenant's budgets and BYO key from the control plane, so with it down a run does not start (fail closed). The kernel reads the
activated policy bundle from its own store, so it keeps enforcing the LAST activated policy; a tenant with no activated policy is DENIED.

## Kernel restart: what is recovered and what is not

| State                        | After a kernel restart                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| tenant policy bundles        | recovered (files)                                                                                                         |
| kill-switches                | recovered when `AXIS_RK_KILL_STATE_FILE` is set (the e2e/chaos stack sets it); a corrupt file REFUSES to start the kernel |
| pending approvals            | LOST (in-memory approvals service): the waiting action is denied, never executed                                          |
| rate-limit / budget counters | LOST (in-memory): windows restart (NEEDS 386)                                                                            |
| audit chain                  | durable in Postgres                                                                                                       |

## Flake handling (honest)

There is no retry decorator and no `sleep`-then-hope: faults are applied through the proxy or process control and observed through the API;
the only waits are bounded polls. Timing assertions are generous (gate timeout is 5 s, bounds are 20-60 s). If a chaos test flakes, that is a
bug in the test or the product: reproduce with `uv run pytest chaos -k <name> --no-cov -x`, read `kernel.err` / `gateway.err` / `runserver.err`
in the pytest tmp directory, fix the cause. Do not add retries.

## Findings of the first runs (all fixed, each with a failing-first test, or recorded in NEEDS)

1. gateway process CRASHED when Postgres dropped an idle pooled connection (unhandled `error` on `pg.Pool`): fixed in every service `main.ts`.
2. kernel restart RELEASED every kill-switch (fail-open): `FileKillSwitchStore` (ADR 0101); multi-instance still needs Redis (NEEDS 383).
3. proxy bug: trickle/jitter reordered bytes and corrupted HTTP/2: fixed with per-direction ordered release.
4. a restart loses pending approvals and in-memory counters (recorded, fail-closed for approvals).
