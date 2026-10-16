# aws/postgres

RDS Postgres 16 (pgvector is available via RDS Postgres extension support;
enabling it is a post-provision `CREATE EXTENSION` step, not Terraform's job)
with gp3 storage, KMS encryption, Multi-AZ, and 14-day backups by default,
matching the control-plane's Postgres 16 + pgvector requirement.

`engine_version` is pinned (`16.4` by default) instead of looked up, so plan
needs no RDS API call to resolve a "latest" version.
