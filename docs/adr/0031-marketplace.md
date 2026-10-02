# 0031. Marketplace: verification, security review, consented installs, takedown; document store with platform and catalog scopes

Status: Accepted · Date: 2026-10-02 · Related: 0030 (registry), 0018 (billing), phase 7 plan component B, `docs/spec/marketplace.md`

## Decisions

1. **Publisher verification** is a state machine `unverified -> pending -> verified | rejected` (rejected may resubmit; moderation may
   suspend verified -> rejected). Evidence (DNS TXT challenge, legal identity) is checked by provers behind interfaces (fakes here) and
   stored append-only. A reviewer can verify only with PASSED evidence from the current submission, and never if they acted for the publisher.
2. **Security review** is `submitted -> automated_scan -> in_review -> approved | rejected | changes_requested`. The scan is static: ABL lint
   plus the capabilities the blueprint asks for (tool kinds and side effects, MCP servers incl. non-https/private hosts, browser/code/egress,
   PHI, memory scopes, budgets, channels, process limits, secret and hidden-behaviour patterns) with severities. Rules: critical findings are
   auto-rejected and can never be approved; every high finding must be acknowledged by id by a human reviewer; automated approval is OFF by
   default (opt-in threshold); the reviewer is never the submitter, a tenant member of the publisher, or anyone who acted for it. An
   approval is **pinned by content hash** and re-verified against the registry at decision time. Versions are immutable, so any republish
   is a new version and needs a new review: only approved versions appear in a listing (`approved[]`), and install resolution reads only that list.
3. **Capabilities and consent.** A blueprint's requests become a sorted set of `{key, level}` (higher level = wider). The permission diff
   against the tenant's baseline (install) or against the install's grant (update) is `added` (new or raised). Install requires the admin
   to echo `consentDigest = sha256(identity + hash + added)` from a fresh preview; install recomputes everything (listing status, approval pin,
   registry verification, scan, diff) so any change in between invalidates the consent (TOCTOU). Updates require re-consent only when the diff
   widens; narrowing updates take the least privilege; downgrades need an explicit flag. The install stores a pinned reference and a
   **recommended policy pack** (schema-validated; `defaultDecision: DENY`, explicit allows for consented tools, high-priority denials for
   code, browser, PHI and long-term memory that were not granted). Nothing activates it automatically.
4. **Takedown.** A moderator can delist a listing or block one version: effective immediately for new installs and updates, registry
   versions are yanked by the platform, existing installs are FLAGGED (state `flagged`, reason, audited in each tenant's chain) not removed.
5. **Metering hook.** An install emits one `marketplace_installs` usage record for the PUBLISHER's tenant with key `marketplace-install:<id>` through
   the billing `UsageSink` (the billing ingest shape); the installer is a hash in the dimensions. Failure never fails the install; unmetered installs
   are retried by `flushMetering`. Payouts are not implemented.
6. **Storage: one document table (migration 0021) with forced RLS and three explicit access paths**: tenant (credential-derived), platform
   (`axis.platform`, set only by the reviewer/moderator/catalog service paths) and catalog (SELECT of `listed` listings). One table keeps
   the policy surface small; optimistic revisions serialise concurrent decisions; `events`, `evidence`, `takedowns` are append-only and
   nothing is deletable. The memory store implements the same scopes and one contract suite runs against both.
7. **Authz and abuse.** Tenant roles come from the control plane ladder (viewer read, builder submit/list, admin verification/baseline/consent/
   install). Staff principals (`reviewer`, `moderator`) are separate credential kinds; wrong-kind credentials are 403. Dev server: tenant only from the
   token, spoofed `tenant_id` is 403, sliding-window rate limits (stricter on submissions and installs), body cap, no stack traces.

## Consequences

- The platform path is as trustworthy as the application code that sets `axis.platform` (same trust as the tenant setting today); a separate
  database role per path is the production hardening (NEEDS).
- Findings are heuristics on declared capabilities, not behavioural analysis: a blueprint cannot do more than it declares (the kernel gates
  every call) but the scan cannot judge prompt intent beyond patterns.
