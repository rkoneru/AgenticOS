output "network_id" {
  value = module.networking.network_id
}

output "gke_cluster_name" {
  value = module.k8s.cluster_name
}

output "postgres_instance_name" {
  value = module.postgres.instance_name
}

output "redis_host" {
  value = module.redis.host
}

output "clickhouse_mig" {
  value = module.clickhouse.instance_group_manager
}

output "object_storage_bucket" {
  value = module.object_storage.bucket_name
}
