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

variable "subnet_cidr" {
  type    = string
  default = "10.70.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range for GKE pod IPs."
  type        = string
  default     = "10.71.0.0/16"
}

variable "services_cidr" {
  description = "Secondary range for GKE service IPs."
  type        = string
  default     = "10.72.0.0/20"
}

variable "enable_nat" {
  type    = bool
  default = true
}
