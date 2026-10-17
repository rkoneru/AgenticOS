# Root composition for one GCP "dedicated tenant" environment: GKE +
# Cloud SQL Postgres 16 + Memorystore Redis + self-managed ClickHouse on a
# MIG + GCS + Cloud KMS.

module "networking" {
  source = "../../modules/gcp/networking"

  project_id = var.project_id
  name       = var.env_name
  region     = var.region
}

module "kms" {
  source = "../../modules/gcp/kms"

  project_id    = var.project_id
  location      = var.region
  key_ring_name = "${var.env_name}-keyring"
}

module "k8s" {
  source = "../../modules/gcp/k8s"

  project_id           = var.project_id
  name                 = "${var.env_name}-gke"
  region               = var.region
  network_self_link    = module.networking.network_self_link
  subnetwork_self_link = module.networking.subnetwork_self_link
  pods_range_name      = module.networking.pods_range_name
  services_range_name  = module.networking.services_range_name
}

module "postgres" {
  source = "../../modules/gcp/postgres"

  project_id        = var.project_id
  name              = "${var.env_name}-pg"
  region            = var.region
  tier              = var.db_tier
  network_self_link = module.networking.network_self_link
}

module "redis" {
  source = "../../modules/gcp/redis"

  project_id        = var.project_id
  name              = "${var.env_name}-redis"
  region            = var.region
  network_self_link = module.networking.network_self_link
}

module "clickhouse" {
  source = "../../modules/gcp/clickhouse"

  project_id           = var.project_id
  name                 = "${var.env_name}-ch"
  image                = var.clickhouse_image
  network_self_link    = module.networking.network_self_link
  subnetwork_self_link = module.networking.subnetwork_self_link
}

module "object_storage" {
  source = "../../modules/gcp/object-storage"

  project_id   = var.project_id
  name         = var.object_storage_bucket_name
  kms_key_name = module.kms.crypto_key_id
}
