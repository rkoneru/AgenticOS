variable "region" {
  type    = string
  default = "us-east-1"
}

variable "dev_plan_mode" {
  description = "true enables the provider's skip_* validation flags for a credential-free `terraform plan`. MUST be false (the default a real deployer should set) for any real apply."
  type        = bool
  default     = false
}

variable "env_name" {
  type    = string
  default = "axis-dedicated"
}

variable "azs" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "cluster_role_arn" {
  type = string
}

variable "node_role_arn" {
  type = string
}

variable "clickhouse_ami_id" {
  type = string
}
