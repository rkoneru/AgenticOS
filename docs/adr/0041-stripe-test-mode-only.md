# 0041. Payment provider interface and Stripe test mode only

Status: Accepted · Date: 2026-10-02

## Context

Hard stop in `CLAUDE.md`: Stripe live mode needs the owner. Phase 6 needs metered billing against Stripe's documented API without
a live account, real keys or network access in CI.

## Decision

- Billing talks to a `PaymentProvider` interface (customers, usage reporting, usage summaries, invoices). Tests use
  `FakePaymentProvider` (strict: idempotency keys, identifier dedupe, fault injection).
- `StripePaymentProvider` implements the interface over the documented REST API (customers, Billing Meter events and event
  summaries, invoice items, invoices) through an injected `HttpTransport`; nothing in the package opens a socket to Stripe.
- TEST MODE ONLY, enforced three ways: the constructor accepts only `sk_test_` / `rk_test_` keys (live, publishable and malformed
  keys throw `LIVE_KEY_REFUSED` without echoing the key); every response with `livemode: true` is refused; webhook events with
  `livemode: true` are refused.
- Every mutation carries an `Idempotency-Key` (derived from stable ids: the invoice id, `tenant:period:meter`); a missing key is
  refused before any request.
- Webhooks: `Stripe-Signature` (`t=`, `v1=`), HMAC-SHA256 over `t.payload` with the raw body, constant-time comparison, tolerance
  window (default 300 s, both directions), duplicate event ids ignored.
- Reconciliation reads; it never repairs. Corrections are explicit, audited adjustments with a reason.

## Consequences

Real test keys, a real HTTP transport and a registered webhook endpoint are NEEDS (docs/NEEDS.md 8xx). The adapter is verified
against request/response shapes written from Stripe's public documentation, not against Stripe.
