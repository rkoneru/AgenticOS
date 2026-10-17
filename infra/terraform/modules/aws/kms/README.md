# aws/kms

A single customer-managed KMS key with rotation enabled and an alias, used
by `modules/aws/postgres` and `modules/aws/object-storage` for
encryption-at-rest. This is a dev-grade stand-in for the "KMS signer" /
real-cloud-KMS work the audit and control-plane services still need
(see `docs/NEEDS.md`): this module only provisions the key, it does not
wire any application to use it for signing.
