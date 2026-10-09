# STRIDE: Marketplace (publishers, review, consented install)

Status: Prototype (fakes for domain and identity provers). Earlier shared model: [registry-marketplace-threat-model.md](registry-marketplace-threat-model.md).

## Assets

- What tenants install: reviewed, hash-pinned blueprint versions and the permission grant of each install.
- Publisher identity and review decisions; the integrity of takedowns.
- Install consent: what the tenant agreed to, bound to a digest.

## Trust boundaries

1. Publisher (untrusted until verified) to submission: static scan plus human review (`services/marketplace/src/scan.ts`, `services/marketplace/src/reviews.ts`).
2. Staff reviewers to decisions: reviewer is never the submitter or anyone who acted for the publisher (`services/marketplace/src/reviews.ts`).
3. Tenant to install: re-resolve, re-verify, re-scan, re-diff at install time, consent digest binds hash and additions (`services/marketplace/src/installs.ts`).

## Data flow

Publisher verification -> listing + submission -> eval gate (hub) -> scan + review decision pinned to the content hash -> registry marks the version public -> tenant previews the permission set -> consent digest -> install writes the grant.

## STRIDE

| Category               | Threat                                       | Mitigation (code path)                                                                                                                                            | Test                                                                           | Residual / NEEDS                                                     |
| ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Spoofing               | A fake publisher claims a domain or identity | Publisher verification by domain and identity provers before listing (`services/marketplace/src/publishers.ts`)                                                   | `services/marketplace/test/flows.test.ts`                                      | Provers are fakes (NEEDS #263)                                       |
| Tampering              | Republish after approval (content swap)      | Versions are immutable; approval pinned to the content hash and re-verified at decision; only `approved[]` is installable (`services/marketplace/src/reviews.ts`) | `services/marketplace/test/hardening.test.ts`                                  | none known                                                           |
| Tampering              | TOCTOU between review and install            | Install re-resolves, re-verifies, re-scans, re-diffs; consent digest binds hash and additions (`services/marketplace/src/installs.ts`)                            | `services/marketplace/test/flows.test.ts`, `e2e/test_phase7_interfaces.py`     | none known                                                           |
| Tampering              | A version that failed evals is listed        | Submit and decide call the injected `EvalGatePort`, default deny (`services/marketplace/src/service.ts`)                                                          | `services/marketplace/test/evals-gate.test.ts`, `e2e/test_phase8_evals.py`     | Tenant-required suites apply only when the hub is wired (NEEDS #298) |
| Repudiation            | A review decision cannot be attributed       | All decisions audited in the publisher's chain, separate credential kinds (`services/marketplace/src/ctx.ts`)                                                     | `services/marketplace/test/core.test.ts`                                       | Two colluding staff are out of scope (NEEDS #274)                    |
| Information disclosure | Cross-tenant install or baseline data        | Forced RLS, tenant from the credential only, 404 for foreign installs (`packages/db/migrations/0011_marketplace.sql`)                                             | `services/marketplace/test/hardening.test.ts`, `e2e/test_phase7_interfaces.py` | none known                                                           |
| Information disclosure | Secrets in a blueprint                       | Scan flags credential patterns as critical, auto-rejected (`services/marketplace/src/scan.ts`)                                                                    | `services/marketplace/test/core.test.ts`                                       | Static and heuristic (NEEDS #264)                                    |
| Denial of service      | Submission or install spam                   | Sliding-window limits stricter on submissions and installs (`services/marketplace/src/service.ts`)                                                                | `services/marketplace/test/dev-server.test.ts`                                 | Per process                                                          |
| Elevation of privilege | Permission creep via an update               | Update diff is against the install's GRANT; widening needs fresh consent (`services/marketplace/src/capabilities.ts`)                                             | `services/marketplace/test/flows.test.ts`                                      | Install does not activate the recommended policy pack (NEEDS #266)   |
| Elevation of privilege | Takedown evasion                             | Takedown is immediate for new installs, yanks registry versions, flags existing installs (`services/marketplace/src/listings.ts`)                                 | `services/marketplace/test/hardening.test.ts`                                  | Running agents keep running until the tenant acts (NEEDS #265)       |

## Prompt injection

Review reads every model-visible text of a blueprint (system prompt, tool descriptions, notices), folds Unicode and whitespace tricks, and flags hidden-behaviour and credential patterns; critical findings are never approvable (`services/marketplace/src/scan.ts`, tests in `services/marketplace/test/hardening.test.ts`). A scan is not a proof: even an approved blueprint runs under the installing tenant's policy and the kernel gates every call. The red-team suite attacks that second layer with injected tool descriptions and tool results.

## Tool misuse

The permission set shown for consent is derived from the declared tools (kind, side effects, MCP servers) and compared at update time (`services/marketplace/src/capabilities.ts`). A tool whose declared `sideEffects` understates what it does is a review matter, not a platform guarantee (NEEDS #399).
