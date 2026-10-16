resource "google_storage_bucket" "this" {
  project       = var.project_id
  name          = var.name
  location      = var.location
  storage_class = var.storage_class

  uniform_bucket_level_access = true

  versioning {
    enabled = var.versioning_enabled
  }

  encryption {
    default_kms_key_name = var.kms_key_name
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 1
      age                = var.noncurrent_version_age_days
    }
    action {
      type = "Delete"
    }
  }

  dynamic "retention_policy" {
    for_each = var.retention_policy_seconds > 0 ? [1] : []
    content {
      retention_period = var.retention_policy_seconds
    }
  }
}
