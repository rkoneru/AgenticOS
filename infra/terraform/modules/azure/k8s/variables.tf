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

variable "dns_prefix" {
  type = string
}

variable "kubernetes_version" {
  description = "Pinned AKS Kubernetes version. Not looked up via `data \"azurerm_kubernetes_service_versions\"`."
  type        = string
  default     = "1.30.5"
}

variable "subnet_id" {
  type = string
}

variable "node_vm_size" {
  type    = string
  default = "Standard_D4s_v5"
}

variable "node_count" {
  type    = number
  default = 2
}

variable "min_count" {
  type    = number
  default = 2
}

variable "max_count" {
  type    = number
  default = 4
}

variable "tags" {
  type    = map(string)
  default = {}
}
