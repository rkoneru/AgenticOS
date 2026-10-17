# Self-managed ClickHouse on an Azure VM Scale Set. Azure (like AWS/GCP) has
# no managed ClickHouse service. `image_reference` has no default: resolving
# "latest" needs a `data "azurerm_platform_image"` lookup (a live Compute
# Gallery/Marketplace API call), avoided here -- see README.

resource "azurerm_linux_virtual_machine_scale_set" "clickhouse" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.vm_size
  instances           = var.instances

  admin_username = var.admin_username
  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  disable_password_authentication = true

  source_image_reference {
    publisher = var.image_reference.publisher
    offer     = var.image_reference.offer
    sku       = var.image_reference.sku
    version   = var.image_reference.version
  }

  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }

  data_disk {
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.data_disk_size_gb
    lun                  = 0
    caching              = "ReadWrite"
  }

  network_interface {
    name    = "${var.name}-nic"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = var.subnet_id
    }
  }

  custom_data = var.custom_data != "" ? var.custom_data : null

  tags = var.tags
}
