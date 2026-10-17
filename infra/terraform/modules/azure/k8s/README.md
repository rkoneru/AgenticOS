# azure/k8s

AKS cluster, system-assigned identity, Azure CNI, autoscaling default node
pool.

## Live-API-dependency note

`kubernetes_version` is pinned, not looked up via
`data "azurerm_kubernetes_service_versions"`. **The azurerm provider has no
documented global flag that skips live credential validation during
plan** the way `aws`'s `skip_credentials_validation` /
`skip_requesting_account_id` / `skip_metadata_api_check` do, and unlike
`google` it performs its OAuth2 token request _eagerly_, during provider
configuration, even for a from-scratch create plan with no data sources.
Setting `ARM_CLIENT_ID` / `ARM_CLIENT_SECRET` / `ARM_SUBSCRIPTION_ID` /
`ARM_TENANT_ID` to fabricated values is not enough: `terraform plan` fails
immediately with a real Azure AD `AADSTS700038` error before Terraform ever
gets to resource-level work -- genuine, documented gap, verified in this
session. See `infra/terraform/envs/azure/README.md` for the exact command
and error observed.
