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

variable "network_self_link" {
  type = string
}

variable "subnetwork_self_link" {
  type = string
}

variable "pods_range_name" {
  type = string
}

variable "services_range_name" {
  type = string
}

variable "kubernetes_version" {
  description = "Pinned GKE master version (e.g. a specific 1.30.x-gke.n release). Not looked up via `data \"google_container_engine_versions\"` -- see README."
  type        = string
  default     = "1.30.5-gke.1443001"
}

variable "node_machine_type" {
  type    = string
  default = "e2-standard-4"
}

variable "node_count_per_zone" {
  type    = number
  default = 2
}

variable "node_disk_size_gb" {
  type    = number
  default = 100
}
