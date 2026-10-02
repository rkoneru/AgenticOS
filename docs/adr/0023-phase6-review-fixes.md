# 0023. Phase 6 independent review: fixes that change behaviour

Status: Accepted · Date: 2026-10-02 · Related: 0018-0022 (billing, control plane, wiring), `docs/NEEDS.md` #206-#213

## Context

An independent adversarial review of Phase 6 (the reviewer did not write the code) found defects that were reproduced with failing
tests first. Contracts stay frozen: no proto, OpenAPI, audit-event or migration change. Most fixes are internal; the ones below
change observable behaviour or policy and are recorded here.

## Decisions

1. **`sso.manage` is owner-only** (policy pack `policies/control-plane`, golden case, RBAC matrix test). With the admin role holding it,
   an admin could link an IdP organization it controls, then sign in through it with the owner's e-mail (members are linked by verified
   e-mail) and receive an owner session: a role-ceiling bypass. Reproduced end to end before the change. `domains.manage` and
   `directories.manage` stay with admins (a directory never yields `owner`; a domain only gates JIT for non-owner roles).
2. **E-mail linking binds one IdP identity.** The first link of a member found by e-mail records `idp:<id>` as its user ref; a later
   identity carrying the same address is denied (`identity_mismatch`, audited). Before, nothing was recorded, so every identity with the
   address signed in as that member. The e2e SCIM test now uses one IdP identity for the "deprovisioned cannot sign in" assertion and
   adds the second-identity assertion.
3. **Policy packs are bounded before validation**: 100 rules and 2000 JSON values per pack, 4000 per active set, and the `opa`
   subprocess has a 60 s timeout. Measured: 300 two-condition rules ~4.5 s, one 20 000-element `in` list ~40 s, 1400 rules minutes, all
   synchronous in the control plane's event loop (a builder holds `policies.publish`).
4. **Bundle publication is serialised per tenant** (in-process queue; each run reads the active set after the previous run wrote).
   Concurrent activations could otherwise write an older set last and drop a later pack from the kernel's bundle.
5. **BYO model keys have an owner** (the last writer) so `deny-others-keys-for-builders` applies to them as the spec states.
6. **Budget limits are bounded** (`<= 1e12`) in the admin API and the runtime reader (`1e308` cost overflowed micro-USD scaling).
7. **Billing**: tenant ids are canonicalised to lower case at every ledger/invoice entry (advisory-lock keys and payload hashes are
   text-derived; an upper-case UUID did not exclude the period sealer's lock and re-labelled duplicates as conflicts); a webhook claim is
   released when its handler fails; `pushUsage` requires a sealed period; an adjustment is validated before it is audited; a meter-wide
   included allowance is one pool across the meter's dimensions (it was granted again per model class).

## Consequences

- Admins lose the IdP link; the owner configures SSO. `docs/NEEDS.md` #207 keeps the remaining trust gaps (unproven org id).
- Pack size limits are a blunt guard; #209 records the worker-pool design that replaces them.
- Pricing change (7): invoices of tenants using several model classes with a meter-wide allowance rise to the contractual figure.
