output "resource_group_name" {
  value = azurerm_resource_group.this.name
}

output "aks_cluster_name" {
  value = module.k8s.cluster_name
}

output "postgres_fqdn" {
  value = module.postgres.fqdn
}

output "redis_hostname" {
  value = module.redis.hostname
}

output "clickhouse_vmss_name" {
  value = module.clickhouse.vmss_name
}

output "storage_account_name" {
  value = module.object_storage.storage_account_name
}
