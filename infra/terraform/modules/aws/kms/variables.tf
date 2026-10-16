variable "alias" {
  description = "KMS key alias, e.g. 'alias/axis-dedicated-tenantx'."
  type        = string
}

variable "description" {
  type    = string
  default = "AXIS data-at-rest encryption key"
}

variable "deletion_window_in_days" {
  type    = number
  default = 30
}

variable "enable_key_rotation" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
