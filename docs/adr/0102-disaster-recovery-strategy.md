# 0102. Disaster recovery: backups, tamper evidence, and the tested restore

Status: Accepted · Date: 2026-10-09 · Related: 0100, 0101

## Context

Targets: RPO <= 5 min, RTO <= 1 h. The platform's data is in one Postgres per region (the audit chain, billing ledger and seals, registry, memory, eval hub).

## Decision

- Backups: physical base backup + continuous WAL archiving (`archive_timeout` 60 s in the design, 2 s in the drill) for PITR, and a nightly logical dump + globals. A per-tenant
  logical export is designed, not built.
- Tamper evidence lives OUTSIDE the database: Ed25519-signed audit checkpoints (and WORM exports). A restore is not accepted until every tenant's chain verifies from genesis AND the
  signed checkpoint matches (a removed tail is invisible to the chain alone).
- Secrets (billing seal key, signer keys, KEKs) are never in the database; a restore needs them from the secret manager. The drill proves seals verify only with the key supplied separately.
- `make dr-drill` is the executable proof: populate, back up, `kill -9` + delete the data directory, restore into fresh clusters (logical and PITR), verify, measure RPO/RTO, and
  prove that a flipped row and a truncated tail in a backup are DETECTED.
- Region failover is DESIGNED only (no real cloud is touched); nothing here is applied.

## Consequences

RPO in the drill is bounded by the WAL archive cadence (acknowledged writes in the unarchived segment are lost); production must monitor archive lag and replicate synchronously if a
zero-loss audit guarantee is wanted (a design decision for Phase 10). In-flight runs and pending approvals are not recoverable in this composition (NEEDS 384, 385).
