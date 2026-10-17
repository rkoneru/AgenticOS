subscription_id = "00000000-0000-0000-0000-000000000000"
tenant_id       = "11111111-1111-1111-1111-111111111111"
location        = "eastus"
env_name        = "axis-dev-dummy"

resource_group_name = "axis-dev-dummy-rg"

db_admin_password = "DummyPlanOnlyPassword123!"

clickhouse_admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyKeyForPlanOnlyValidationNeverUsed dummy@axis"

clickhouse_image_reference = {
  publisher = "Canonical"
  offer     = "0001-com-ubuntu-server-jammy"
  sku       = "22_04-lts"
  version   = "latest"
}

storage_account_name = "axisdevdummysa"
key_vault_name       = "axis-dev-dummy-kv"

postgres_private_dns_zone_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/axis-dev-dummy-rg/providers/Microsoft.Network/privateDnsZones/privatelink.postgres.database.azure.com"
