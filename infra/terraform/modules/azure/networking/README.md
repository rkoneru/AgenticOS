# azure/networking

A VNet with a dedicated AKS subnet and a delegated data subnet (for Postgres
Flexible Server VNet integration), plus an optional NAT gateway for AKS
egress. `location` and CIDRs are variables with documented defaults; no
`data "azurerm_..."` lookups are used.
