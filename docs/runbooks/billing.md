# Runbook: billing and usage ledger

Dev stack only (library + loopback server; `docs/spec/billing.md`).

## Run and test

```bash
pnpm --filter @axis/billing test        # real Postgres 16 via infra/scripts/with-pg.sh
pnpm --filter @axis/billing cov         # thresholds: 95% on ledger/money/rating/provider safety, 85% elsewhere
cd services/billing && node scripts-mutation.mjs [substring]   # one safety edit at a time; every mutant must be killed
AXIS_BILLING_DATABASE_URL=... AXIS_BILLING_TOKENS='{"tok":{"tenantId":"<uuid>","scopes":["read"],"subject":"svc"}}' \
  AXIS_BILLING_SEAL_KEY=<32+ chars> node services/billing/dist/main.js      # prints "listening <port>"
```

## Month end

1. `BillingService.closeAndRate(tenant, "YYYY-MM")`: seals the period (after the month has ended), stores invoice revision N.
2. `pushUsage(tenant, period, customerId)`, then `pushInvoice(...)` (both idempotent; safe to retry).
3. `reconcile(tenant, period, customerId)`. A clean report is the exit condition.

## A discrepancy

Do not edit anything. Read the report kind (`docs/spec/billing.md` section 5).

- `usage_missing_at_provider` / `usage_quantity_mismatch`: resend with `pushUsage` (same identifiers); if the provider still
  differs, the provider holds a stale or duplicated event (look at `usage_duplicated_at_provider`).
- Ledger wrong (a real double count): post an adjustment (`POST /v1/usage/adjustments`, admin token, reason required). It lands in
  the current open period and is audited; the closed period is untouched. Re-rate the NEXT period normally.
- Invoice differs: `rateSealed` creates a new revision from the sealed totals; send it; never edit the provider invoice by hand
  without a matching adjustment.

## Suspected tampering

`ledger.verifySeal(tenant, period)` recomputes the digest, totals, hash and signature. `{ok:false, reason}` means rows or the seal
changed after closing (an owner bypassed the triggers or the key differs). Treat as a security incident (audit chain, DB access logs).
`ledger.conflicts(tenant)` lists same-key/different-payload attempts (forgery or a producer bug).

## Late events

An event for an already sealed month is accepted and counted in the next open month (`original_period_id` shows where it
belongs). If the customer must be credited for the sealed month, post an explicit adjustment with a reason.
