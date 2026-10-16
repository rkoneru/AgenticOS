resource "azurerm_postgresql_flexible_server" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name

  version    = var.postgres_version
  sku_name   = var.sku_name
  storage_mb = var.storage_mb

  backup_retention_days = var.backup_retention_days
  zone                  = var.zone

  dynamic "high_availability" {
    for_each = var.high_availability_mode != "" ? [1] : []
    content {
      mode = var.high_availability_mode
    }
  }

  administrator_login    = var.administrator_login
  administrator_password = var.administrator_password

  delegated_subnet_id = var.delegated_subnet_id
  private_dns_zone_id = var.private_dns_zone_id

  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "axis" {
  name      = "axis"
  server_id = azurerm_postgresql_flexible_server.this.id
  collation = "en_US.utf8"
  charset   = "utf8"
}
