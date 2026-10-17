# gcp/object-storage

Uniform-bucket-level-access GCS bucket, versioned, CMEK-encrypted via
`kms_key_name`, with a noncurrent-version cleanup lifecycle rule.
`retention_policy_seconds` optionally enables WORM-style retention (the GCS
analogue of S3 Object Lock) but defaults off, same caveat as
`modules/aws/object-storage`: the audit service's WORM export is not built
yet.
