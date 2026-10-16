output "cluster_name" {
  value = azurerm_kubernetes_cluster.this.name
}

output "kube_config_host" {
  value     = azurerm_kubernetes_cluster.this.kube_config[0].host
  sensitive = true
}

output "cluster_identity_principal_id" {
  value = azurerm_kubernetes_cluster.this.identity[0].principal_id
}
