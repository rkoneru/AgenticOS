variable "project_id" {
  type = string
}

variable "name" {
  type = string
}

variable "zone" {
  type    = string
  default = "us-east1-b"
}

variable "image" {
  description = "Full image self-link or family (e.g. 'projects/debian-cloud/global/images/family/debian-12') for the ClickHouse node. No default -- GCP (like AWS/Azure) has no managed ClickHouse service, and this module deliberately does not use a `data \"google_compute_image\"` 'latest in family' lookup, so callers must pin an exact image."
  type        = string
}

variable "machine_type" {
  type    = string
  default = "n2-standard-8"
}

variable "data_disk_size_gb" {
  type    = number
  default = 500
}

variable "target_size" {
  type    = number
  default = 3
}

variable "network_self_link" {
  type = string
}

variable "subnetwork_self_link" {
  type = string
}

variable "startup_script" {
  description = "Startup script that installs/configures ClickHouse. Defaults to empty for plan-only validation."
  type        = string
  default     = ""
}
