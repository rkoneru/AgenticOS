output "instance_group_manager" {
  value = google_compute_instance_group_manager.this.name
}

output "instance_template" {
  value = google_compute_instance_template.this.name
}
