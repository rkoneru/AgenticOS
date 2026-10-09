# 0103. Defects found by the load test: audit append contention and per-run memory

Status: Accepted · Date: 2026-10-09 · Related: 0100

## Context

`make loadtest` found two defects with measurable impact.

## Decision

1. **Run service memory (~5.2 MB per run, never freed).** Each run created three default `httpx.AsyncClient`s; each loads the CA bundle into its own SSL context (~1.7 MB). After ~2000
   runs the run service held 2.3 GB. `axis_runtime._tls.shared_ssl_context()` is built once and passed to every client (trust behaviour unchanged). Regression test: 150 per-run client trios
   grew resident memory by 765 MiB before, under 120 MiB after. The bypass-guard allowlist gained `_tls.py` (httpx, ssl; it opens no connection).
2. **Audit append retry storm.** `PgAuditLog.append` was optimistic (take the per-tenant lock only after losing a race), so concurrent writers to one chain failed the DB chain guard and
   retried: 8 callers on one chain got 170 appends/s, fewer than 1 caller (271/s). It now takes the lock on the first statement: 8 callers 264/s, 32 callers 234/s. Test: 60 parallel appends with
   `maxAttempts: 1` all succeed (fails on the old code). The retry loop remains as a backstop. The test that simulated a racer slipping in between the duplicate check and the head read was removed because that interleaving can no longer occur between two PgAuditLog writers.
3. `GW_MAX_SSE_STREAMS` makes the per-tenant SSE stream cap (default 16, unchanged) configurable; the load test raises it.

## Consequences

One audit chain per tenant still serialises appends (about 270/s here, about 3.3 ms of Postgres round trips each): this is the gate's capacity ceiling per tenant (NEEDS 381).
