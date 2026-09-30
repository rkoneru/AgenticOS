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
- **Trust boundary (ADR-0008):** tamper-_evident_, not tamper-proof. The table owner or a superuser can disable triggers and
  delete the tail, and the remaining prefix still verifies. Detecting that needs signed head checkpoints and WORM export,
  **which are planned and not built**. Until then owner and superuser are trusted.
- **Tamper evidence:** `verifyChain` reports the first broken `seq` and whether it was a gap, broken link, altered content,
  or cross-tenant splice.
- **AGIL** reads this log only; it never writes to it and is never consulted for decisions.
