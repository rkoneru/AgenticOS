# gcp/postgres

Cloud SQL for Postgres 16, regional HA, PITR enabled, private-IP only
(requires a VPC peering / Private Service Access setup this module does not
itself create -- see the `envs/gcp` root for the composition point).
`database_version` is a pinned string (`POSTGRES_16`), not looked up.
