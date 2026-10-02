# Billing and usage metering (Phase 6 B)

Status: Prototype (library + loopback dev server; no live Stripe, no real ClickHouse, no tax). Code: `services/billing`,
runtime emitter `runtime/src/axis_runtime/usage.py`. Decisions: ADR 0040 (schema), ADR 0041 (Stripe test mode).

## 1. Meters

A quantity is an integer in the meter's smallest unit; there are no floats in the ledger.

| Meter                  | Unit          | Source                                           | Rated by      |
| ---------------------- | ------------- | ------------------------------------------------ | ------------- |
| `tokens_in`            | token         | `model_call` (input minus cached), ALLOWed only  | `model_class` |
| `tokens_out`           | token         | `model_call`                                     | `model_class` |
| `runtime_seconds`      | ms            | `process_transition`: time a process is RUNNING  | -             |
| `tool_executions`      | execution     | `tool_call_result` ok, ALLOWed only              | `tool_kind`   |
| `voice_minutes`        | ms            | `voice_call` phase `ended`, `duration_ms`        | -             |
| `storage_gb_hours`     | milli-GB-hour | hourly sample (`storageSample`, rounded half up) | -             |
| `marketplace_installs` | install       | `marketplaceInstall`                             | -             |

Dimensions (<= 8 keys, `[a-z][a-z0-9_]{0,31}` -> 1..128 chars): `agent`, `run`, `model`, `provider`, `model_class`, `tool_kind`,
`call`, `listing`. Only the rate dimension changes the price; the rest are for analysis and the statement.
`tool_kind` is derived from the enforcement point: `tool`, `mcp`, `code`, `browser`, `memory_write`, `message`.

### What is not billed

- A denied, blocked, approval-pending or kill-switched action: it has no `tool_call_result`/`model_call`, and the service also
  requires an ALLOW or ALLOW_WITH_REDACTION `gate_decision` with the same `action_id` before it bills any result.
- A failed execution (`ok = false`).
- A cache or rules hit in NEXUS (no `model_call` happens) and provider-cached input tokens: zero model tokens.
- Speech sessions (`stt`/`tts` results at the `model_call` enforcement point) as tool executions; voice is billed by call time.

## 2. Ledger

`usage_events` is insert-only. `idempotency_key` is unique per tenant. A replay with an identical payload hash is a no-op that
returns the original entry; the same key with a different payload is rejected with status `conflict` and a row in `usage_conflicts`.
Out-of-order arrival changes nothing: totals are sums. `eventTime` may not be more than 5 minutes in the future.

Corrections are `adjustment` entries (signed, non-zero, mandatory `reason` and `actor`, optional `corrects_key`), created only by
`AdjustmentApi`, which appends an audit event first (no audit, no change).

### Periods, rollups and seals

Periods are UTC months (`YYYY-MM`). Rollups (`hour`, `day`, `month`) bucket by EVENT time in UTC and are informational; billing
uses periods. `closePeriod` is allowed only after the month has ended and once. It writes a seal: `seq` and `prev_seal_hash` (a
chain per tenant), `rows_digest` (SHA-256 over the sorted `(key, payload hash)` pairs), `totals`, `closed_at`, and an HMAC
signature. `verifySeal` recomputes all of it from the stored rows. A late event whose month is sealed counts in the first
unsealed later month and keeps `original_period_id`; a sealed period never changes (also enforced by a DB trigger).

## 3. Price book, plans and rating

A `PriceBook` (`id`, `version`, `currency`) holds `RateCard`s: a meter, a rate-dimension value (`""` = fallback) and graduated
tiers `{upTo, price: {amountMicro per perUnits}}`. A `Plan` binds one price book version, a base fee, included quantities (per
`meter` or `meter:dimension`), and a committed minimum. `rate(...)` is pure and deterministic:

1. Base fee, prorated by the seconds the plan was active in the period (adjacent windows sum exactly to the whole month).
2. Per rate key: included allowance first, then graduated tiers; one line per tier used. A net-negative quantity (adjustments)
   becomes a credit line priced at tier 1. Usage with no rate is NOT charged: it is listed in `warnings` (`unpriced usage`).
3. Committed use: if the usage charges are below the commitment, the shortfall is a `commit_true_up` line.
4. Credits are consumed first-in-first-out up to the positive subtotal and spread over the positive lines.
5. Tax is a placeholder (0); NEEDS.

### Rounding rules (integer arithmetic only)

- R1 A price is `amountMicro` micro-currency per `perUnits` base units. A charge is `round(quantity * amountMicro / perUnits)`.
- R2 `round` is half away from zero. Charges round once per invoice line, never per record.
- R3 Splitting an amount over weights (credits over lines) uses largest remainder: the shares sum exactly to the total, ties go
  to the lower index, zero weight gets nothing.
- R4 Converting lines to the minor unit (cents, 10 000 micro-USD) uses cumulative rounding: the minor lines sum to
  `round(total)` exactly.

Invariants (property-tested): `sum(line.amount) == subtotal`; `sum(line.net) + tax == total`; credits never exceed the positive
subtotal and never exceed a line; allocation and minor-unit conversion never create or lose a unit; rating is deterministic.

## 4. Providers (Stripe test mode)

`PaymentProvider`: `createCustomer`, `reportUsage` (one meter event per tenant, period and meter, identifier
`axis:<tenant>:<period>:<meter>`, net total clamped at zero), `usageSummary`, `createInvoice` (invoice items then a draft invoice),
`getInvoice`, `listInvoices`. See ADR 0041 for the live-key refusal, idempotency keys and webhook verification.

## 5. Reconciliation

`reconcile` compares, per tenant and period: ledger totals vs provider-reported usage per meter vs our rated invoice (in minor
units) vs the provider's invoice. It is read-only and returns a report; it never writes.

| Kind                            | Meaning                                                             |
| ------------------------------- | ------------------------------------------------------------------- |
| `usage_missing_at_provider`     | ledger has usage, provider has none                                 |
| `usage_quantity_mismatch`       | both have usage, totals differ (delta in `detail`)                  |
| `usage_orphan_at_provider`      | provider has usage the ledger lacks                                 |
| `usage_duplicated_at_provider`  | one identifier stored more than once (when the provider lists them) |
| `invoice_missing_at_provider`   | rated invoice with no provider invoice                              |
| `invoice_duplicate_at_provider` | more than one provider invoice for the period                       |
| `invoice_total_mismatch`        | totals differ                                                       |
| `invoice_line_mismatch`         | line amount differs (by position)                                   |
| `invoice_missing_line`          | a line of ours is absent at the provider                            |
| `invoice_orphan_line`           | a provider line (or invoice) with no counterpart of ours            |

Fixing a discrepancy is a human decision: repair the provider side, or post an audited adjustment.

## 6. Dev HTTP surface (`dev-server.ts`)

Loopback, static bearer tokens, refuses `NODE_ENV=production`. The tenant always comes from the token; a different `tenant_id` is a 403. Scopes: `read` (GET `periods`, `statement`, `rollup`, `entries`: read-only), `ingest` (POST `run-events`: the trusted runtime),
`admin` (POST `adjustments`, actor = the token's subject). Bigints are decimal strings on the wire.

## 7. Runtime emitter

`HttpUsageEmitter.emit_run(log, run_id)` posts a WHITELISTED projection of the run log (`BILLING_FIELDS`: ids, counts, durations,
decisions; no tool arguments or results, no text or audio). Resending everything is safe (idempotent keys). A failure raises
`UsageUnavailable`; metering is never on the decision path. `services/billing/test/fixtures/run-projection.json` is a golden file
checked by both the Python and the TypeScript tests.
