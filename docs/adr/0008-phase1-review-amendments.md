# 0008. Phase 1 review amendments and stated trust boundaries

Status: Accepted · Date: 2026-09-30 · Amends: 0006, 0007 (post-freeze change)

## Context

An independent review of Phase 1 found one integrity blocker and several overstated or missing guarantees. Contracts were
frozen (ADR-0007), so every change below is a deliberate post-freeze change: new migration `0004_hardening.sql` (migrations
are append-only), plus additive/clarifying edits to the audit schema and proto comments. No consumers exist yet, so no
version bump is needed; the manifest was regenerated with this ADR.

## Changes

1. **search_path hijack (blocker, fixed).** Guard functions resolved tables via `pg_temp` first, so an `axis_app` session could
   shadow `audit_events` with a TEMP table and forge chain continuity. Fix: every function in schema `axis` pins
   `search_path = pg_catalog, pg_temp` and qualifies names; `TEMPORARY` is revoked from PUBLIC. Regression tests reproduce the
   attack and assert every `axis` function pins `search_path`.
2. **Audit hash reproducibility.** `ts` must match `YYYY-MM-DDTHH:mm:ss.SSSZ`, UUIDs are lowercase canonical, so a row read back
   from `timestamptz`/`uuid` re-serialises to the same canonical string. A DB round-trip test verifies a chain after storage.
3. **State guards in the DB:** gapless `run_events.sequence`; `terminated` absorbing for runs/processes; identity columns
   immutable; approvals decided once with immutable SLA/roles and complete decision metadata; `risk_level` must equal the ABL
   document's `riskClassification.level`; API-key prefix unique per tenant (no cross-tenant existence leak).
4. **Contract notes:** gate/audit protos now state server rules (tenant derived from credentials, reject unspecified enums and
   non-canonical values).

## Stated trust boundaries (previously implicit)

- **Tenant scope is a transaction-local setting.** RLS protects against forgotten filters and cross-tenant bugs in trusted
  services. It does **not** stop a fully compromised `axis_app` session, which can `set_config` to another tenant (a test pins
  this). Regulated and dedicated tiers must use per-tenant credentials (dedicated DB) and, later, signed tenant binding;
  shared-tier services must never execute tenant-supplied SQL.
- **Audit integrity is tamper-evident, not tamper-proof.** The table owner/superuser can disable triggers and delete the log's
  tail; `verifyChain` over the remaining prefix would still pass. Detecting tail truncation needs an external anchor: periodic
  signed head checkpoints plus WORM export. **Neither is built yet** (planned, Phase 2 audit service). Until then, owner and
  superuser are trusted.
- **Planned, not built:** a separate migration-owner role, an audited `axis_admin` path, WORM export, an API-key authentication
  lookup route (needs a dedicated audited definer path; Phase 6).
- **Global kill-switch** is platform state in the gate's Redis flag (ADR-0004), not a tenant DB row; the tenant `kill_switches`
  table intentionally holds tenant/agent/tool scopes only.
- Any session may request the audit advisory lock and stall a tenant's audit writes (availability, not integrity).

## Consequences

Contract gaps the review listed (tenant admin, members, API keys, BYO-credential, retention, DSAR endpoints; a retention
field; `region` enumeration) are additive and tracked in `docs/NEEDS.md` for Phases 6 and 9.
