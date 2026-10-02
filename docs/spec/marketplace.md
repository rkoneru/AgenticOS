# Marketplace (Phase 7 B)

Status: Prototype (library + non-production loopback dev server; Postgres store with forced RLS; domain/identity proofs are FAKES; no payouts).
Code: `services/marketplace` (`@axis/marketplace`) over `@axis/registry`. Decisions: ADR 0031.

## 1. Roles

| Principal                  | Can                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------- |
| tenant admin/owner         | start publisher verification, submit evidence, set the tenant baseline, preview/install/update/uninstall |
| tenant builder             | submit versions for review, create listings                                                              |
| tenant viewer              | read                                                                                                     |
| reviewer (platform staff)  | decide publisher verifications and security reviews. Never for their own organisation                    |
| moderator (platform staff) | takedown listings/versions, suspend publishers                                                           |
| anonymous                  | public catalog reads                                                                                     |

## 2. Publisher verification

`unverified -> pending -> verified | rejected`; `rejected -> pending` (resubmit); `verified -> rejected` (suspension). `start` issues a DNS TXT
challenge (`axis-verify=<token>`); `submitEvidence` runs the domain and identity provers and appends one evidence row each; the reviewer
approves only with passed evidence from the current submission. Every step is audited in the publisher's tenant chain.

## 3. Security review

`submitted -> automated_scan -> in_review -> approved | rejected | changes_requested` (last three terminal; `automated_scan` may reject
or, if configured, approve). Review id = `<publisher tenant>|<ns>/<name>@<version>` (one review per immutable version).

Scan finding ids (stable): `SEC-LINT-*`, `SEC-TOOL-001/002` (external/write side effects), `SEC-EXEC-001` (code), `SEC-EGRESS-001/002`
(browser, custom model endpoint), `SEC-MCP-001`, `SEC-NET-001..003` (bad URL, not https, private/raw-IP host), `SEC-CHAN-001/002`,
`SEC-AGENT-001`, `SEC-DATA-001..003` (PHI, PHI+long-term memory, PHI+consumer channel), `SEC-MEM-001/002`, `SEC-BUDGET-001/002`, `SEC-PROC-001/002`,
`SEC-POLICY-001`, `SEC-SECRET-001` (critical), `SEC-PROMPT-001` (high), `SEC-PROMPT-002`. Severities: info < low < medium < high < critical.

Decision rules: reviewer is staff and not the submitter / a member of the publisher tenant / anyone who acted for the publisher; note of 10-2000
characters; approve needs: no critical finding, all high finding ids in `acknowledged`, publisher still verified, registry version re-verified
and its content hash equal to the reviewed hash. On approval the namespace becomes public in the registry and the version is added to the listing's
`approved[]` pinned to that hash.

## 4. Listings and the catalog

A verified publisher creates a listing per `<ns>/<name>` (status `draft` until a version is approved, then `listed`; `taken_down` by moderation).
`GET /v1/catalog` and `/v1/catalog/{ns}/{name}` need no credential and show only listed listings and their approved, unblocked versions.

## 5. Install, consent, update, uninstall

Capabilities (`{key, level}`; higher level = wider): `model:<provider>`, `egress:endpoint:<host>`, `tool:<kind>:<name>` (level = side-effect rank
none 1, read 2, write 3, external 4), `mcp:<url>`, `exec:code`, `egress:browser`, `memory:*`, `data:phi`, `channel:<c>`, `budget:<metric>` (level = hard cap,
unbounded = 1e15), `process:max_children`, `process:restart_always`. Default tenant baseline: `memory:run`.

- `preview(ns, name, range)` -> version, hash, findings, capabilities, diff vs baseline, `consentDigest`.
- `install({ns, name, version, contentHash, consentDigest})`: re-evaluates everything; digest and hash must match; creates the pinned reference
  (`namespace, name, version, contentHash`), the grant, the recommended policy pack stub and one `marketplace_installs` usage record for the publisher.
- `update(ns, name, {version, consentDigest?, allowDowngrade?})`: `updatePreview` gives the digest; widening needs it; narrowing does not; lower versions need
  `allowDowngrade`.
- `uninstall`: state `uninstalled`, pack dropped. Reinstall is a new install (new metering record).
- Takedown: listing or version delisted immediately; registry versions yanked; installs flagged (`flagged` + reason); new installs/updates refused.

## 6. Metering

`marketplace_installs` quantity 1, dimensions `{listing, version, installer: sha256(tenant)[:16]}`, key `marketplace-install:<install id>`, tenant = publisher,
source `marketplace`, through the billing `UsageSink` (accepted by the real in-memory ledger in tests). Failure leaves `meteredAt = null`;
`flushMetering` retries safely. Publisher payouts: not implemented (NEEDS).

## 6a. Public API (OpenAPI 1.2.0, ADR 0053)

Tenant side only, under `/v1/marketplace/*`: catalog, listing, `installs/preview` (diff, findings, `consent_digest`), `installs` (digest + hash must match a fresh evaluation, else 409),
list, uninstall. Publisher onboarding, review decisions, listing creation and takedown stay outside the API (NEEDS #274); the e2e drives them through the services.

## 7. Storage

Migration `0011_marketplace.sql`: `marketplace_docs` (collections `publishers evidence listings reviews events installs baselines takedowns`),
forced RLS with tenant / platform / catalog policies, optimistic `rev`, append-only collections, no deletes.
