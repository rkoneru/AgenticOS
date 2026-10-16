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

variable "vnet_cidr" {
  type    = string
  default = "10.80.0.0/16"
}

variable "aks_subnet_cidr" {
  type    = string
  default = "10.80.0.0/20"
}

variable "data_subnet_cidr" {
  description = "Subnet for Postgres Flexible Server / Redis private endpoints."
  type        = string
  default     = "10.80.16.0/24"
}

variable "enable_nat_gateway" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
