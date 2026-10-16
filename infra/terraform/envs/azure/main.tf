# Root composition for one Azure "dedicated tenant" environment: AKS +
# Postgres Flexible Server 16 + Azure Cache for Redis + self-managed
# ClickHouse on a VMSS + Storage Account + Key Vault.

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
}

module "networking" {
  source = "../../modules/azure/networking"

  name                = var.env_name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
}

module "kms" {
  source = "../../modules/azure/kms"

  name                = var.key_vault_name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tenant_id           = var.tenant_id
}

module "k8s" {
  source = "../../modules/azure/k8s"

  name                = "${var.env_name}-aks"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = var.env_name
  subnet_id           = module.networking.aks_subnet_id
}

module "postgres" {
  source = "../../modules/azure/postgres"

  name                   = "${var.env_name}-pg"
  location               = var.location
  resource_group_name    = azurerm_resource_group.this.name
  administrator_password = var.db_admin_password
  delegated_subnet_id    = module.networking.data_subnet_id
  private_dns_zone_id    = var.postgres_private_dns_zone_id
}

module "redis" {
  source = "../../modules/azure/redis"

  name                = "${var.env_name}-redis"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
}

module "clickhouse" {
  source = "../../modules/azure/clickhouse"

  name                 = "${var.env_name}-ch"
  location             = var.location
  resource_group_name  = azurerm_resource_group.this.name
  subnet_id            = module.networking.aks_subnet_id
  admin_ssh_public_key = var.clickhouse_admin_ssh_public_key
  image_reference      = var.clickhouse_image_reference
}

module "object_storage" {
  source = "../../modules/azure/object-storage"

  name                = var.storage_account_name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
}
