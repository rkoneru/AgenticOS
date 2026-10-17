resource "azurerm_redis_cache" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name

  sku_name = var.sku_name
  family   = var.family
  capacity = var.capacity

  minimum_tls_version = var.minimum_tls_version
  redis_version       = var.redis_version

  tags = var.tags
}
