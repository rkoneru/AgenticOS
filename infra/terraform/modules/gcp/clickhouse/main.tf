# Self-managed ClickHouse on a GCE managed instance group. GCP has no
# managed ClickHouse product, so AXIS self-hosts it here (bare VM option) or
# via the Phase 10 Helm chart on the modules/gcp/k8s cluster. `image` is a
# required variable (exact image, not a "latest in family" data lookup) --
# see README.

resource "google_compute_instance_template" "this" {
  project      = var.project_id
  name_prefix  = "${var.name}-"
  machine_type = var.machine_type
  region       = null

  disk {
    source_image = var.image
    auto_delete  = true
    boot         = true
  }

  disk {
    disk_size_gb = var.data_disk_size_gb
    disk_type    = "pd-ssd"
    auto_delete  = false
    boot         = false
  }

  network_interface {
    network    = var.network_self_link
    subnetwork = var.subnetwork_self_link
  }

  metadata_startup_script = var.startup_script

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "this" {
  project            = var.project_id
  name               = "${var.name}-mig"
  base_instance_name = var.name
  zone               = var.zone
  target_size        = var.target_size

  version {
    instance_template = google_compute_instance_template.this.id
  }
}
