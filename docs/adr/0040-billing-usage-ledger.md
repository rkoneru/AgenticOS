# 0040. Billing usage ledger schema (migration 0008)

Status: Accepted · Date: 2026-10-02 · Amends: 0007 (post-freeze addition, same procedure as 0008, 0010, 0013 and 0015)
(Number and migration version chosen on branch p6/billing; the integrating branch renumbers on collision, together with the
migration file name and `FREEZE.json`.)

## Context

Phase 6 component B (`services/billing`) meters usage and rates it into invoices. Migrations 0001-0007 have no usage, period or
invoice table. Contracts stay frozen: the audit event shape, proto and OpenAPI do not change. The runtime already records what we
need in its event log (`model_call` tokens, `gate_decision` + `tool_call_result`, `voice_call` durations, `process_transition`
timestamps), so no runtime contract changes either (the runtime forwards a projection of its own log).

## Decision

1. Additive migration `0008_billing.sql` (nothing existing altered): `usage_events`, `billing_period_seals`, `usage_conflicts`,
   `invoices`, `invoice_provider_links`. All carry `tenant_id` and FORCED RLS through `axis.enable_tenant_rls`, granted
   `SELECT, INSERT` only to `axis_app`, and carry `forbid_mutation` triggers (UPDATE, DELETE, TRUNCATE) that also bind the table
   owner. Corrections are compensating entries, never edits.
2. Idempotency is the table's `UNIQUE (tenant_id, idempotency_key)`. The key is per tenant and per source event
   (`run:<run_id>:<seq>:<meter>` for runtime usage). `payload_hash` (SHA-256 of the canonical event, excluding receipt time and the
   period it landed in) tells a replay (same hash: no-op, the original row is returned) from a forgery or bug (different hash:
   rejected, reported in `usage_conflicts`, original untouched).
3. Quantities are integers in the meter's smallest unit, `bigint`, within +-(2^53-1) (a CHECK), so JS and SQL agree and sums are
   exact (`sum(...)::numeric`, BigInt in code). Usage rows are `>= 0`; an `adjustment` row is signed, non-zero and requires a reason
   and an actor (CHECK). Money is integer micro-currency.
4. Billing periods are UTC calendar months. Closing a period writes one row to `billing_period_seals`: hash chain per tenant
   (`seq`, `prev_seal_hash`), digest of every (key, payload hash) in the period, totals, and an HMAC signature (`SealSigner`; KMS is
   NEEDS). A BEFORE INSERT trigger on `usage_events` refuses a row whose `period_id` is sealed, under a shared advisory lock that
   the sealer takes exclusively, so a close and a concurrent insert cannot interleave. The service attributes a late event (event
   time in a sealed month) to the first unsealed later month and records `original_period_id`: a late event is an adjustment of
   the next period, never a change to a closed one.
5. `invoices` are immutable; re-rating a period inserts the next `revision`. Provider linkage is a separate insert-only row.
6. ClickHouse is a non-authoritative analytics sink behind an interface (fake in tests); the Postgres ledger decides.

## Consequences

- Tests: `services/billing` on real Postgres 16 (forced RLS, trigger refusals, tamper detection, concurrent close/insert),
  `packages/db` migration list, contract freeze regenerated.
- The ledger cannot be corrected in place by anyone, including an operator with owner rights, without disabling triggers, which
  `verifySeal` then detects for closed periods.
- Cost: one shared advisory lock per insert (cheap, uncontended except while a period is being sealed).
