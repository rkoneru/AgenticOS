# Runbook: audit service

Package `@axis/audit` (`services/audit`) · Spec `docs/spec/audit-log.md` · ADR-0008, ADR-0010 · Status: **Built** (library; no network service yet)

## Trust boundary (read this first)

- The hash chain is **tamper-evident**, not tamper-proof. The database enforces append-only and chain continuity with triggers,
  but the table owner and any superuser can disable triggers, rewrite rows, and delete the tail.
- `verifyChain` / `verify()` detects edits, reordering and deleted **middle** rows. It does **not** detect a deleted **tail**:
  the remaining prefix is a valid chain. This is proven by a test (`pg.test.ts`, "a deleted TAIL is NOT detected...").
- A **signed checkpoint** pins `(tenant, seq, hash)` under an Ed25519 key the DB operator does not hold. With a checkpoint,
  truncation, rewrite and forged signatures are detected. A **WORM export** gives a third party an offline-verifiable copy.
- Residual risk: whoever holds both the signing key and database owner rights can forge a consistent history, and someone who
  can delete every checkpoint **and** the tail wins unless a copy exists off-box. Keep the private key in KMS (planned, NEEDS #12),
  and keep the latest checkpoint and WORM segments in storage the database operator cannot modify (NEEDS #13, #14).
- The app role (`axis_app`) can only SELECT and INSERT; the service must connect as `axis_app`, never as owner. Tenant RLS applies
  to reads and writes; every call is scoped by `withTenant`.

## Verify

```ts
const log = new PgAuditLog({ pool }); // pool connects as axis_app
await log.verify(tenantId); // whole chain
await log.verify(tenantId, { fromSeq: 1_000_000 }); // slice; uses seq-1 as anchor and checks its hash
```

Verdict is `{ ok: true, length }` or `{ ok: false, brokenAtSeq, reason }` with reason `hash_mismatch` (content altered),
`prev_hash_mismatch` (link broken), `seq_gap` (row deleted), `tenant_mismatch`. Reads are paged (500 rows). Treat any `ok: false`
as a security incident: stop exporting/checkpointing that tenant, preserve the database, compare against the last checkpoint and
the most recent WORM export to find the first divergence.

## Checkpoints

```ts
const cp = new AuditCheckpointer(log, new PgCheckpointStore({ pool }), signer);
const checkpoint = await cp.createCheckpoint(tenantId);
const verdict = await cp.verifyAgainstCheckpoint(tenantId, checkpoint, publicKey);
```

`verifyAgainstCheckpoint` checks, in order: shape, Ed25519 signature, tenant, head not behind the checkpoint (`truncated`), hash at the
checkpoint seq (`hash_mismatch` = history rewritten), and the chain from genesis to the checkpoint seq (`chain_broken`).

**Cadence recommendation** (tune per tenant tier): every 5 minutes or 10,000 events, whichever is first, for regulated and
dedicated tenants; hourly for standard. Each run: `verify` the new slice since the last checkpoint, then `createCheckpoint`, then copy the
checkpoint off-box. `createCheckpoint` does not verify by itself; never checkpoint a tenant whose last `verify` failed. The window of
undetectable tail deletion is the checkpoint interval. Checkpoints in `audit_checkpoints` are append-only and the DB refuses one
whose `(seq, hash)` is not in the chain, but the DB is not the trust anchor: also publish each checkpoint to storage outside the DB
operator's control and verify with a public key distributed separately. Rotating the signing key: keep old public keys to verify old checkpoints.

## Export to WORM

```ts
await exportRange(log, tenantId, 1, toSeq, new FileWormSink("/mnt/worm/<tenant>/<export-id>"), {
  segmentSize: 1000,
});
const verdict = await verifyExport(new FileWormSink("/mnt/worm/<tenant>/<export-id>")); // offline, no DB
```

- Layout: `segment-000001.ndjson` ... (canonical JSON, one event per line, `segmentSize` events each) and `manifest.json` written
  **last**: tenant, first/last seq, count, `first_prev_hash` (anchor for slices), `head_hash`, and each segment's SHA-256.
- The export verifies the chain as it reads and aborts rather than exporting a broken chain. Use a **fresh sink path per export**:
  sinks are write-once, so re-exporting into a used path fails with `WormOverwriteError`, and a path without `manifest.json` is an
  incomplete export that must be abandoned (segments cannot be deleted through the sink).
- Incremental exports: export `[lastExported+1, head]`; the manifest records the anchor hash, and `verifyExport` checks the slice
  links to it. Compare `last_seq`/`head_hash` of each export with the signed checkpoint at that seq to bind the export to the trusted head.
- `FileWormSink` is write-once in software only (temp file + fsync + `link(2)` which refuses existing names, then directory fsync). It
  is not immutable against someone with filesystem access. The S3 Object Lock implementation is **planned, not built** (NEEDS #13).

## Restore from export

There is no automated restore yet; the procedure is manual and must be done as the schema owner during maintenance, with the tenant
quiesced:

1. `verifyExport` every export for the tenant and confirm the newest `head_hash` matches a signed checkpoint (`verifyAgainstCheckpoint`).
2. Decide the authoritative range: exports are authoritative for the seqs they cover. Find the first divergence with `verify()` and
   by comparing database rows with the segments (same seq, different hash).
3. Preserve the damaged table (`CREATE TABLE audit_events_damaged_<date> AS SELECT ...` or a snapshot) as evidence.
4. As owner, disable the append-only trigger only for the repair session (`ALTER TABLE audit_events DISABLE TRIGGER audit_append_only`),
   delete rows from the first divergent seq upward for that tenant, and insert the events from the segments in seq order (columns map 1:1
   to event fields; `ts` is the event's ISO string). Keep `audit_chain_guard` **enabled**: it re-validates seq and prev_hash as rows go in.
   Re-enable the trigger and run `verify()` for the whole tenant; expect `ok`. Events newer than the last export cannot be recovered from it:
   record the loss window (last export `last_seq` to the pre-incident head) in the incident report.
5. `createCheckpoint` for the restored head and record the incident and the restore in the audit log itself (`enforcement_point: "admin"`).

## Appending (for service authors)

- Use `AuditSink.append`; a rejected append means the action must be treated as DENY (fail-closed, invariant 1).
- Supplying `id` makes the append idempotent (safe to retry after a timeout): same id and same content returns the stored event, different
  content throws `AuditConflictError`. `ts` is assigned when absent (and ignored when comparing replays if it was not supplied).
- Callers must not supply `seq`, `prev_hash` or `hash`.
- Concurrent appends to one tenant serialize in the database. An append that loses a race is retried (up to 5 attempts; retries take the
  same per-tenant advisory lock the DB guard uses). Exhaustion throws `AuditAppendError` and nothing was stored.
- AGIL reads through `createAuditReader(store)` (`listEvents` only). Never hand AGIL a sink.
