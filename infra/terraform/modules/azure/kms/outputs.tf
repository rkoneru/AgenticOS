output "key_vault_id" {
  value = azurerm_key_vault.this.id
}

output "key_id" {
  value = azurerm_key_vault_key.this.id
}
