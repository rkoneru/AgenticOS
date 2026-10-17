variable "subscription_id" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "env_name" {
  type    = string
  default = "axis-dedicated"
}

variable "resource_group_name" {
  type = string
}

variable "db_admin_password" {
  type      = string
  sensitive = true
}

variable "clickhouse_admin_ssh_public_key" {
  type = string
}

variable "clickhouse_image_reference" {
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
}

variable "storage_account_name" {
  type = string
}

variable "key_vault_name" {
  type = string
}

variable "postgres_private_dns_zone_id" {
  description = "ID of a pre-created private DNS zone for Postgres Flexible Server VNet integration (e.g. privatelink.postgres.database.azure.com). Not managed by this root -- DNS zone lifecycle is handled once per subscription/vnet, not per environment."
  type        = string
}
