variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-east1"
}

variable "env_name" {
  type    = string
  default = "axis-dedicated"
}

variable "db_tier" {
  type    = string
  default = "db-custom-4-16384"
}

variable "clickhouse_image" {
  type = string
}

variable "object_storage_bucket_name" {
  type = string
}
