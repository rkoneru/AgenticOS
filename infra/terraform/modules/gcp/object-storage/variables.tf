variable "project_id" {
  type = string
}

variable "name" {
  type = string
}

variable "location" {
  type    = string
  default = "US-EAST1"
}

variable "storage_class" {
  type    = string
  default = "STANDARD"
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name for default bucket encryption."
  type        = string
}

variable "noncurrent_version_age_days" {
  type    = number
  default = 90
}

variable "retention_policy_seconds" {
  description = "WORM retention in seconds. 0 disables the retention policy (no bucket lock)."
  type        = number
  default     = 0
}
