# STRIDE: Blueprint registry (signed supply chain)

Status: Prototype (Postgres stores, signed publish, verified resolve). Earlier shared model with the marketplace: [registry-marketplace-threat-model.md](registry-marketplace-threat-model.md).

## Assets

- What runs in tenants: blueprint versions (immutable, signed, content-addressed).
- Publisher keys and namespaces; eval attestations bound to a content hash.
- Private namespace confidentiality per tenant.

## Trust boundaries

1. Publisher tooling (offline signing, private key never leaves) to the registry publish API (`services/registry/src/signing.ts`).
2. Registry to its store (tamperable by a storage attacker): verify on EVERY read (`services/registry/src/verify.ts`).
3. Registry to the Eval Hub gate port: default DENY_ALL (`services/registry/src/eval-gate.ts`).

## Data flow

Publish: canonical ABL + provenance (compiler lint reproduction) signed by a namespace key -> verification (schema, hash, signature, key window, provenance subject) -> immutable row. Resolve: semver range -> newest verifying version, never falling back to an older one on failure -> response with verification result.

## STRIDE

| Category               | Threat                                                   | Mitigation (code path)                                                                                                                                                             | Test                                                                         | Residual / NEEDS                                                                                   |
| ---------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Spoofing               | Typosquatting or look-alike namespaces and names         | `UNIQUE(normalized)` with folding of case, hyphens and look-alike characters, reserved words (`services/registry/src/service.ts`)                                                  | `services/registry/test/service.test.ts`                                     | none known                                                                                         |
| Spoofing               | Forged provenance (signed but lying)                     | Subject and ABL digest recomputed, lint counts and codes must reproduce (`services/registry/src/provenance.ts`)                                                                    | `services/registry/test/verify.test.ts`                                      | Publisher keys are held by publishers (NEEDS #261)                                                 |
| Tampering              | Storage tampering or forged rows                         | Verify on read: canonical text, schema, hash, strict base64 signature, key window; a property test flips every character of every signed field (`services/registry/src/verify.ts`) | `services/registry/test/properties.test.ts`, `e2e/test_phase7_interfaces.py` | No transparency log (NEEDS #260)                                                                   |
| Tampering              | Rollback or stale-version attack                         | Resolve never falls back to an older version; `notBelow` lock; yank is final (`services/registry/src/semver.ts`, `services/registry/src/service.ts`)                               | `services/registry/test/semver.test.ts`                                      | none known                                                                                         |
| Tampering              | Release of a version that failed its evals               | `setVersionPublic` calls the injected `EvalGatePort`, an error denies (`services/registry/src/eval-gate.ts`)                                                                       | `services/registry/test/eval-gate.test.ts`, `e2e/test_phase8_evals.py`       | The registry asks the gate only for declared suites unless the hub adds tenant suites (NEEDS #298) |
| Repudiation            | A mutation without an audit record                       | ALLOW/DENY written before and after; an unwritable decision is not performed (`services/registry/src/audit.ts`)                                                                    | `services/registry/test/service.test.ts`                                     | none known                                                                                         |
| Information disclosure | Private namespace visible to others                      | Forced RLS; private namespaces answer 404 to other tenants (`packages/db/migrations/0010_registry.sql`)                                                                            | `services/registry/test/stores.test.ts`, `e2e/test_phase7_interfaces.py`     | none known                                                                                         |
| Denial of service      | Publish flood or huge bodies                             | Body caps and sliding-window limits (`services/registry/src/http-kit.ts`)                                                                                                          | `services/registry/test/dev-server.test.ts`                                  | Dev server limits are per process                                                                  |
| Elevation of privilege | Key compromise lets an attacker publish as the namespace | Per-namespace keys with effective times; revoke as compromised distrusts everything the key signed (`services/registry/src/signing.ts`)                                            | `services/registry/test/verify.test.ts`                                      | Installers learn of a revoked key only through failed verification (NEEDS #270)                    |
| Elevation of privilege | A tenant publishes into someone else's namespace         | Namespaces are single-tenant, writes need the owner (`services/registry/src/authz.ts`)                                                                                             | `services/registry/test/service.test.ts`, `e2e/test_phase7_interfaces.py`    | Marketplace authority is application-level (NEEDS #262)                                            |

## Prompt injection

A blueprint carries model-visible text (system prompt, tool descriptions). Registry verification proves who published it and that it is unchanged, not that the text is benign; the review scan reads every model-visible string and folds unicode tricks before flagging hidden instructions (see [stride-marketplace.md](stride-marketplace.md)). The red-team suite includes tool-description injection (cases with technique `tool-description` in `evals/redteam/datasets/redteam-core.json`): the description text is obeyed by the scripted model, and the kernel still gates the resulting calls.

## Tool misuse

The registry has no agent-callable tool. A blueprint can declare tools with a `sideEffects` label, which the baseline policy trusts for read tools (the label is the blueprint author's claim, NEEDS #399); registry-side lint and the marketplace scan flag capability declarations for review.
