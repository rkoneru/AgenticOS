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

variable "tier" {
  type    = string
  default = "STANDARD_HA"
}

variable "memory_size_gb" {
  type    = number
  default = 8
}

variable "redis_version" {
  description = "Pinned Memorystore Redis version (not looked up)."
  type        = string
  default     = "REDIS_7_2"
}

variable "network_self_link" {
  type = string
}

variable "transit_encryption_mode" {
  type    = string
  default = "SERVER_AUTHENTICATION"
}
