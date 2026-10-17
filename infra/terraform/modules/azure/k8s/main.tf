# AKS cluster with one default node pool (autoscaling). `kubernetes_version`
# is a pinned variable -- not resolved via `data "azurerm_kubernetes_service_versions"`
# ("latest supported" lookup) -- so `validate` needs no live AKS version API call.

resource "azurerm_kubernetes_cluster" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.dns_prefix
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name                = "default"
    vm_size             = var.node_vm_size
    vnet_subnet_id      = var.subnet_id
    node_count          = var.node_count
    enable_auto_scaling = true
    min_count           = var.min_count
    max_count           = var.max_count
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
  }

  tags = var.tags
}
