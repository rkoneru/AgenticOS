resource "azurerm_storage_account" "this" {
  name                     = var.name
  location                 = var.location
  resource_group_name      = var.resource_group_name
  account_tier             = var.account_tier
  account_replication_type = var.account_replication_type
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = var.versioning_enabled

    delete_retention_policy {
      days = var.blob_soft_delete_retention_days
    }
  }

  dynamic "immutability_policy" {
    for_each = var.immutability_enabled ? [1] : []
    content {
      allow_protected_append_writes = false
      period_since_creation_in_days = var.immutability_period_days
      state                         = "Unlocked"
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "this" {
  name                  = var.container_name
  storage_account_name  = azurerm_storage_account.this.name
  container_access_type = "private"
}
