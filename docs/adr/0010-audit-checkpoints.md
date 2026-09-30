# 0010. Signed audit head checkpoints (migration 0005)

Status: Accepted · Date: 2026-09-30

## Context

ADR-0008 records that the audit log is tamper-_evident_ only against parties who cannot disable triggers: a table owner or
superuser can delete the **tail** of a chain and the remaining prefix still passes `verifyChain`. Phase 2 (component D) builds the
mitigation planned there.

## Decision

- New table `audit_checkpoints (tenant_id, id, seq, hash, ts, signature, created_at)`, added by **additive** migration
  `0005_audit_checkpoints.sql`. It follows 0004 conventions: tenant RLS via `axis.enable_tenant_rls` (SELECT, INSERT only),
  `axis.forbid_mutation` append-only and no-truncate triggers, and a search_path-pinned guard function
  (`axis.audit_checkpoint_guard`) that refuses a checkpoint whose `(seq, hash)` does not exist in the tenant's chain.
- A checkpoint is `{tenant_id, seq, hash, ts, signature}`. The Ed25519 signature covers
  `"axis-audit-checkpoint-v1\n" + canonical_json({tenant_id, seq, hash, ts})`, made by a `Signer` whose private key the database
  and the audit table owner do not hold. Verifying the log against a checkpoint fails on: invalid signature, head behind the
  checkpoint seq (truncation), or a different hash at that seq (rewrite).
- This is an allowed post-freeze addition: no existing migration or frozen schema is edited; `FREEZE.json` is regenerated so the
  freeze guard covers the new file. Existing db tests are extended only so their meta-tests still pass (seed covers the new table,
  migration list).
- Checkpoints are only as strong as where they live. The recommended deployment exports them (and WORM segments) to storage
  outside the database operator's control; see `docs/runbooks/audit.md`. A KMS-backed `Signer` and S3 Object Lock `WormSink` are
  planned, not built (`docs/NEEDS.md`).

## Consequences

- Residual risk: an attacker holding both the signing key and DB owner rights can forge a consistent history; an attacker who
  removes the newest checkpoints along with the tail is only caught if a later copy exists off-box. Cadence guidance is in the runbook.
