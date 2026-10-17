# Azure Key Vault + one key. `tenant_id` is an input variable, not resolved
# via `data "azurerm_client_config"` (which needs a live Azure AD/ARM call),
# so this module's shape alone does not force a live lookup -- though the
# azurerm provider's own authentication still needs one (see envs/azure/README.md).

resource "azurerm_key_vault" "this" {
  name                       = var.name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = var.sku_name
  purge_protection_enabled   = var.purge_protection_enabled
  soft_delete_retention_days = var.soft_delete_retention_days

  tags = var.tags
}

resource "azurerm_key_vault_key" "this" {
  name         = var.key_name
  key_vault_id = azurerm_key_vault.this.id
  key_type     = var.key_type
  key_size     = var.key_size

  key_opts = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
}
