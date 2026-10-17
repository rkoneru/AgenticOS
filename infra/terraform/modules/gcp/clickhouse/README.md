# gcp/clickhouse

Self-managed ClickHouse on a zonal managed instance group with a separate
pd-ssd data disk per node. GCP has no managed ClickHouse service. `image`
has no default: resolving a "latest in family" image needs a
`data "google_compute_image"` lookup (a live Compute Images API call), which
this project avoids for `plan`-without-credentials reasons -- callers must
pin an exact image self-link.
