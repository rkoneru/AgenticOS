# azure/clickhouse

Self-managed ClickHouse on a Linux VM Scale Set with a Premium_LRS OS disk
and one Premium_LRS data disk per instance. Azure has no managed ClickHouse
service. `image_reference` has no default: picking "latest" would need a
`data "azurerm_platform_image"` lookup (a live call), avoided per this
project's plan-without-credentials constraint -- callers must pin an exact
`publisher/offer/sku/version`. `admin_ssh_public_key` also has no default on
purpose (no sane fake key should ever be checked in).
