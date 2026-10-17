output "instance_name" {
  value = google_sql_database_instance.this.name
}

output "private_ip_address" {
  value = google_sql_database_instance.this.private_ip_address
}

output "connection_name" {
  value = google_sql_database_instance.this.connection_name
}
