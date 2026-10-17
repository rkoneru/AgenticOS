variable "identifier" {
  type = string
}

variable "engine_version" {
  description = "Postgres engine version. Pinned explicitly (no data-source lookup of 'latest')."
  type        = string
  default     = "16.4"
}

variable "instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "allocated_storage_gb" {
  type    = number
  default = 100
}

variable "max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling. 0 disables autoscaling."
  type        = number
  default     = 500
}

variable "db_name" {
  type    = string
  default = "axis"
}

variable "username" {
  type    = string
  default = "axis_admin"
}

variable "password" {
  description = "Master password. Pass via a tfvars file that is never committed, or a secrets manager reference; dummy.tfvars uses a placeholder only for `plan`."
  type        = string
  sensitive   = true
}

variable "subnet_ids" {
  description = "Private subnet IDs for the DB subnet group."
  type        = list(string)
}

variable "vpc_security_group_ids" {
  type = list(string)
}

variable "multi_az" {
  type    = bool
  default = true
}

variable "backup_retention_days" {
  type    = number
  default = 14
}

variable "kms_key_arn" {
  description = "KMS key ARN for storage encryption (from modules/aws/kms)."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
