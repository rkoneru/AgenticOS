# Audit log and hash chain

Status: **Frozen (v1)** · Schema: `packages/contracts/schemas/audit-event-v1.schema.json` · Reference: `packages/contracts/src/audit-chain.ts`

One chain **per tenant**. Each event carries: tenant, actor (human/agent+PID/system), blueprint name+version, policy version,
enforcement point, action, decision, `inputs_hash`, `outputs_hash`, `trace_id`, `seq`, `prev_hash`, `hash`.

- `ts` is UTC with exactly millisecond precision and a trailing `Z`; UUIDs are lowercase; this keeps the hash reproducible from
  `timestamptz`/`uuid` columns (round-trip tested).
- `seq` starts at 1 and is gapless. Genesis `prev_hash` is 64 zeros.
- `hash = SHA-256( canonical_json(event without hash) )` where canonical JSON has sorted keys, no whitespace, integers only
  (floats are rejected so every language produces identical bytes).
- `inputs_hash` / `outputs_hash` are `SHA-256(canonical_json(payload))`. Raw payloads are not in the audit row (PHI stays out).
- **Database enforcement** (migration 0003): append-only (UPDATE/DELETE/TRUNCATE blocked), and a trigger enforces `seq = head+1`
  and `prev_hash = head.hash` under a per-tenant advisory lock. The database does not recompute `hash`; the audit service and
  `verifyChain` do, and the WORM export lets a third party re-verify offline.
- **Trust boundary (ADR-0008, ADR-0010):** tamper-_evident_, not tamper-proof. The table owner or a superuser can disable triggers and
  delete the tail, and the remaining prefix still verifies (`verifyChain` cannot see a missing tail). Detection needs a **signed head
  checkpoint** (`audit_checkpoints`, Ed25519 over `axis-audit-checkpoint-v1\n` + canonical JSON of `{tenant_id, seq, hash, ts}`) and/or a
  **WORM export** (NDJSON segments + manifest with per-segment SHA-256, anchor and head hash, verifiable offline). Both are built in
  `@axis/audit`; the KMS signer and S3 Object Lock sink are planned (`docs/NEEDS.md` #12, #13). They are only as strong as where the
  key and the copies live: owner and superuser remain trusted for anything not yet checkpointed or exported. Operations: `docs/runbooks/audit.md`.
- **Append semantics (`@axis/audit`):** `id` (lowercase uuid v4) and `ts` (UTC, ms, `Z`) are assigned when absent; the sealed event is
  validated against the audit schema before storage; a client-supplied `id` makes append idempotent (same content returns the stored
  event, different content is a conflict); an append is acknowledged only after COMMIT; callers never supply `seq`/`prev_hash`/`hash`.
- **Tamper evidence:** `verifyChain` reports the first broken `seq` and whether it was a gap, broken link, altered content,
  or cross-tenant splice.
- **AGIL** reads this log only; it never writes to it and is never consulted for decisions.
