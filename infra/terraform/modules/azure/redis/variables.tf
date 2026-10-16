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

variable "sku_name" {
  type    = string
  default = "Premium"
}

variable "family" {
  type    = string
  default = "P"
}

variable "capacity" {
  type    = number
  default = 1
}

variable "minimum_tls_version" {
  type    = string
  default = "1.2"
}

variable "redis_version" {
  description = "Pinned Redis major version string (not looked up)."
  type        = string
  default     = "6"
}

variable "tags" {
  type    = map(string)
  default = {}
}
