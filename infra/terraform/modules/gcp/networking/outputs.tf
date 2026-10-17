output "network_id" {
  value = google_compute_network.this.id
}

output "network_self_link" {
  value = google_compute_network.this.self_link
}

output "subnetwork_self_link" {
  value = google_compute_subnetwork.this.self_link
}

output "pods_range_name" {
  value = "${var.name}-pods"
}

output "services_range_name" {
  value = "${var.name}-services"
}
