variable "name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "resource_group_name" {
  type = string
}

variable "postgres_version" {
  description = "Pinned Postgres Flexible Server major version (not looked up)."
  type        = string
  default     = "16"
}

variable "sku_name" {
  type    = string
  default = "GP_Standard_D4s_v3"
}

variable "storage_mb" {
  type    = number
  default = 131072
}

variable "backup_retention_days" {
  type    = number
  default = 14
}

variable "zone" {
  type    = string
  default = "1"
}

variable "high_availability_mode" {
  type    = string
  default = "ZoneRedundant"
}

variable "administrator_login" {
  type    = string
  default = "axis_admin"
}

variable "administrator_password" {
  type      = string
  sensitive = true
}

variable "delegated_subnet_id" {
  type = string
}

variable "private_dns_zone_id" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
