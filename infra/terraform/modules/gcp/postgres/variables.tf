variable "project_id" {
  type = string
}

variable "name" {
  type = string
}

variable "region" {
  type    = string
  default = "us-east1"
}

variable "database_version" {
  description = "Pinned Cloud SQL Postgres version (not looked up)."
  type        = string
  default     = "POSTGRES_16"
}

variable "tier" {
  type    = string
  default = "db-custom-4-16384"
}

variable "network_self_link" {
  type = string
}

variable "availability_type" {
  type    = string
  default = "REGIONAL"
}

variable "disk_size_gb" {
  type    = number
  default = 100
}

variable "backup_retention_days" {
  type    = number
  default = 14
}

variable "deletion_protection" {
  type    = bool
  default = true
}
