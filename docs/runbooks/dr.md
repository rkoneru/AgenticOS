# Runbook: disaster recovery (`make dr-drill`)

Phase 9 D. **Status: restore procedure TESTED on local throwaway Postgres 16 clusters; multi-region failover is DESIGNED only (no real cloud).**
Targets (master prompt section 7): RPO <= 5 min, RTO <= 1 h. Measured values: [docs/nfr.md](../nfr.md) (small data; not extrapolated).

## What must be recoverable

| Asset                                                                                                                     | Where                                                                                                                         | Backed up by                                             | Verified after restore by                                                         |
| ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------- |
| all tenant data incl. the hash-chained audit log, checkpoints, billing ledger and seals, registry, memory, eval hub, runs | Postgres                                                                                                                      | logical dump + base backup + WAL archive                 | `e2e/scripts/dr-ops.mjs verify`                                                   |
| signed audit checkpoints (the tamper-evidence anchor)                                                                     | OUTSIDE the database (the checkpoint signer's public key + the latest signed checkpoint per tenant, exported to WORM storage) | audit export / `exportRange` to object lock              | chain head must contain the checkpoint                                            |
| billing seal HMAC key, checkpoint signing key, envelope KMS keys, BYO model keys' KEK                                     | KMS / secret manager, NEVER in the database                                                                                   | KMS multi-region key replication / key escrow (designed) | seals verify only if the key is restored (the drill passes the key in separately) |
| policy bundles                                                                                                            | control plane store + bundle store                                                                                            | with the database                                        | tenant gets its policy back                                                       |
| run state of in-flight runs                                                                                               | run service memory (dev composition)                                                                                          | NOT recoverable (NEEDS 384)                             | runs are re-started by the caller                                                 |

## Strategy

1. **Continuous**: physical base backup daily + WAL archiving with `archive_timeout = 60 s` (design) to a second region/account bucket with
   object lock. The drill uses `archive_timeout = 2 s` so the RPO window is visible in seconds.
2. **Logical**: `pg_dump` of the application database + `pg_dumpall --globals-only` (roles) nightly; kept 35 days. A per-tenant export (rows by
   `tenant_id`, in dependency order) is DESIGNED for tenant-level restore and DSAR; not built.
3. **Tamper evidence**: at least hourly, `AuditCheckpointer.createCheckpoint` per tenant (Ed25519) and `exportRange` to WORM storage. After ANY
   restore, `verifyAgainstCheckpoint` MUST pass before the stack is reopened: it catches a flipped row (hash chain) and a removed tail (a head
   behind the checkpoint) that the chain alone cannot see.
4. **Region failover (designed, not built)**: warm standby Postgres in a second region fed by WAL streaming (RPO = replication lag, alarm at 60 s),
   DNS failover with health checks, KMS keys replicated, stateless services started from the same images. RTO budget: detect 5 min, decide 10 min,
   promote 5 min, DNS/TTL 5 min, verify 15 min, reopen 5 min = 45 min < 1 h. NOT demonstrated.

## Restore procedure (what the drill does)

1. Provision a fresh Postgres 16 with pgvector. Restore roles (`globals.sql`, minus the bootstrap superuser).
2. Logical: create the database, `psql -f logical.sql`. Physical: copy the base backup to the data directory, add `recovery.signal`, set
   `restore_command` to the WAL archive, start, wait until `pg_is_in_recovery()` is false.
3. Restore the secrets (seal key, signer public key) from the secret manager / WORM anchor.
4. Run the verification (below). Only if ALL checks pass, point the services at the new database and reopen.
5. Re-create anything that lived only in process memory: pending approvals (re-request), in-flight runs (re-start), rate-limit counters.

## The drill: `make dr-drill`

Populates 3 tenants on a real stack running on a WAL-archiving Postgres (runs incl. a policy-denied one, audit chains, memory entries, a signed
registry publish, eval datasets, a SEALED past billing period, signed audit checkpoints), takes a logical and a physical backup, writes more
runs, then `kill -9`s the postmaster and DELETES the data directory. It restores both ways into fresh clusters and checks, per tenant:

- audit chain verification from genesis;
- chain head equals the pre-backup head (logical) / the pre-backup head is inside the restored chain (physical);
- the signed checkpoint (held outside the database) matches;
- RLS: a tenant sees 0 rows of another tenant; the app role with no tenant set sees 0 audit rows;
- row count and content hash of every tenant table equal the manifest taken at backup time (logical);
- billing seal verification; registry resolve (hash, signature, provenance);
- RPO: acknowledged audit events not recovered, and the window in seconds; RTO: restore + verification wall time.

Negative drills (must be DETECTED or the drill fails): a dump with one audit decision flipped (hash chain breaks); a dump with a tenant's
audit tail removed (signed checkpoint reports truncation).

Results: `infra/dr/results/dr-drill.{json,md}`.

## Limits

Tiny data set (the verify-time and append-rate measurements for large chains are in the load test); same machine; no network between regions;
no real KMS; the restore of in-flight runs and approvals is not possible in this composition.
