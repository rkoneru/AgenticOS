variable "project_id" {
  type = string
}

variable "location" {
  type    = string
  default = "us-east1"
}

variable "key_ring_name" {
  type = string
}

variable "crypto_key_name" {
  type    = string
  default = "axis-data-key"
}

variable "rotation_period" {
  description = "Rotation period as a duration string, e.g. '7776000s' (90 days)."
  type        = string
  default     = "7776000s"
}
