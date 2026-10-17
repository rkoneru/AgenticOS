# gcp/kms

A KMS key ring and one rotating crypto key, used by `modules/gcp/postgres`
(via CMEK, wired at the `envs/gcp` level) and `modules/gcp/object-storage`.
Dev-grade stand-in only, same caveat as `modules/aws/kms`.
