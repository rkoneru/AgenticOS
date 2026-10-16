variable "name" {
  description = "Storage account name. Must be globally unique, lowercase, 3-24 chars, no hyphens."
  type        = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "resource_group_name" {
  type = string
}

variable "account_tier" {
  type    = string
  default = "Standard"
}

variable "account_replication_type" {
  type    = string
  default = "GZRS"
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "container_name" {
  type    = string
  default = "axis-data"
}

variable "blob_soft_delete_retention_days" {
  type    = number
  default = 30
}

variable "immutability_enabled" {
  description = "Enable account-level immutability policy (WORM). Defaults off, same caveat as the AWS/GCP modules."
  type        = bool
  default     = false
}

variable "immutability_period_days" {
  type    = number
  default = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}
