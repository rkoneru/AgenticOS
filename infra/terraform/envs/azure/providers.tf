# The azurerm provider has no documented global "skip live validation" flag
# the way aws does. `features {}` is required by the provider even when no
# feature-block behavior is needed. Real auth normally comes from
# ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_SUBSCRIPTION_ID / ARM_TENANT_ID
# env vars or `az login`; for a dummy/plan-only run those four env vars are
# set to fabricated values (see envs/azure/README.md for the result).

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}
