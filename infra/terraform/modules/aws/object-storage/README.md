# aws/object-storage

Private S3 bucket: versioned, SSE-KMS encrypted, public access fully
blocked, with a noncurrent-version expiration lifecycle rule.
`object_lock_enabled` is exposed but defaults off -- the audit service's
WORM export (S3 Object Lock) is NOT built yet (see `docs/NEEDS.md`); turning
this on is necessary but not sufficient without that application-side work.
