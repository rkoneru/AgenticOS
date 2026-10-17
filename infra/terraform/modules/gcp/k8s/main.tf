# GKE regional cluster with one managed node pool. `kubernetes_version` is a
# pinned variable (not `data "google_container_engine_versions"`'s "latest"
# lookup) so `terraform plan` never needs that live GKE API call.

resource "google_container_cluster" "this" {
  project  = var.project_id
  name     = var.name
  location = var.region

  network    = var.network_self_link
  subnetwork = var.subnetwork_self_link

  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = var.kubernetes_version

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  release_channel {
    channel = "UNSPECIFIED"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}

resource "google_container_node_pool" "default" {
  project    = var.project_id
  name       = "${var.name}-default"
  location   = var.region
  cluster    = google_container_cluster.this.name
  node_count = var.node_count_per_zone

  node_config {
    machine_type = var.node_machine_type
    disk_size_gb = var.node_disk_size_gb
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  management {
    auto_repair  = true
    auto_upgrade = false
  }
}
