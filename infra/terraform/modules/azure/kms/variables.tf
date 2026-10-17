variable "name" {
  description = "Key Vault name. Must be globally unique, 3-24 chars."
  type        = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "resource_group_name" {
  type = string
}

variable "tenant_id" {
  description = "Azure AD tenant ID that owns this Key Vault. A variable, not looked up via `data \"azurerm_client_config\"`, so plan does not need a live Azure AD call."
  type        = string
}

variable "sku_name" {
  type    = string
  default = "premium"
}

variable "purge_protection_enabled" {
  type    = bool
  default = true
}

variable "soft_delete_retention_days" {
  type    = number
  default = 90
}

variable "key_name" {
  type    = string
  default = "axis-data-key"
}

variable "key_type" {
  type    = string
  default = "RSA"
}

variable "key_size" {
  type    = number
  default = 4096
}

variable "tags" {
  type    = map(string)
  default = {}
}
