# azure/object-storage

Geo-zone-redundant (GZRS) storage account, TLS 1.2 minimum, blob versioning
and soft-delete, one private container. `immutability_enabled` optionally
turns on an account-level immutability policy (the Azure analogue of S3
Object Lock / GCS bucket retention), off by default -- same WORM caveat as
the other two clouds' object-storage modules.
