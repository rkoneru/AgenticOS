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

variable "subnet_id" {
  type = string
}

variable "vm_size" {
  type    = string
  default = "Standard_D8s_v5"
}

variable "instances" {
  type    = number
  default = 3
}

variable "admin_username" {
  type    = string
  default = "axisadmin"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for the VMSS admin user. No default -- callers must supply a real key."
  type        = string
}

variable "image_reference" {
  description = "Exact marketplace image reference (publisher/offer/sku/version). No default: this project avoids a `data \"azurerm_platform_image\"` 'latest version' lookup (a live call), so callers must pin an exact version string."
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
}

variable "data_disk_size_gb" {
  type    = number
  default = 500
}

variable "custom_data" {
  description = "Base64-encoded cloud-init that installs/configures ClickHouse. Empty by default for plan-only validation."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
