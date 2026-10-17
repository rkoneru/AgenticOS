# azure/kms

An Azure Key Vault (premium SKU, purge protection on) with one RSA-4096
encryption key. `tenant_id` is a plain variable rather than
`data "azurerm_client_config"`, so the module itself adds no extra live
lookup beyond what provider authentication already requires. Dev-grade
stand-in only, same caveat as the AWS/GCP kms modules.
