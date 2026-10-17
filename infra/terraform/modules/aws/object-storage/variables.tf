variable "bucket_name" {
  type = string
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "kms_key_arn" {
  description = "KMS key ARN for SSE-KMS bucket encryption."
  type        = string
}

variable "noncurrent_version_expiration_days" {
  type    = number
  default = 90
}

variable "object_lock_enabled" {
  description = "Enable S3 Object Lock (WORM) -- needed for the audit-export WORM requirement (ADR 0102 / NEEDS: S3 Object Lock not built yet)."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
