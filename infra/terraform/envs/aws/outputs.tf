output "vpc_id" {
  value = module.networking.vpc_id
}

output "eks_cluster_name" {
  value = module.k8s.cluster_name
}

output "eks_endpoint" {
  value = module.k8s.cluster_endpoint
}

output "postgres_endpoint" {
  value = module.postgres.endpoint
}

output "redis_primary_endpoint" {
  value = module.redis.primary_endpoint_address
}

output "clickhouse_asg_name" {
  value = module.clickhouse.autoscaling_group_name
}

output "audit_export_bucket" {
  value = module.object_storage.bucket_name
}
