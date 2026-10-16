resource "google_sql_database_instance" "this" {
  project          = var.project_id
  name             = var.name
  region           = var.region
  database_version = var.database_version

  deletion_protection = var.deletion_protection

  settings {
    tier              = var.tier
    availability_type = var.availability_type
    disk_size         = var.disk_size_gb
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = var.backup_retention_days
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_self_link
    }
  }
}

resource "google_sql_database" "axis" {
  project  = var.project_id
  name     = "axis"
  instance = google_sql_database_instance.this.name
}
