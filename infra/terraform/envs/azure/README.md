# envs/azure

Root composition of every `modules/azure/*` module into one "dedicated
tenant" Azure environment (AKS + Postgres Flexible Server 16 + Azure Cache
for Redis + self-managed ClickHouse on a VMSS + Storage Account + Key
Vault).

## Dummy-credential plan: real commands and results

```
export ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000
export ARM_CLIENT_SECRET=dummy
export ARM_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
export ARM_TENANT_ID=11111111-1111-1111-1111-111111111111
terraform init -backend=false
terraform validate
terraform plan -var-file=dummy.tfvars
```

`terraform validate` passes with no credentials. `terraform plan` does not:
the azurerm provider has no documented flag to skip the live Azure AD
OAuth2 token request made while configuring the provider, and -- unlike
`google` -- it performs that request eagerly, during provider
configuration, before Terraform even looks at what resources would be
created. Real result captured in this session: `terraform plan
-var-file=dummy.tfvars` with fabricated `ARM_CLIENT_ID` /
`ARM_CLIENT_SECRET` / `ARM_SUBSCRIPTION_ID` / `ARM_TENANT_ID` exits 1:

```
Error: building account: could not acquire access token to parse claims: clientCredentialsToken: received HTTP status 400 with response: {"error":"unauthorized_client","error_description":"AADSTS700038: 00000000-0000-0000-0000-000000000000 is not a valid application identifier. ..."}
  with provider["registry.terraform.io/hashicorp/azurerm"],
  on providers.tf line 8, in provider "azurerm":
   8: provider "azurerm" {
```

This is a genuine, unresolved gap for Azure: a `plan` here cannot be
verified without a real Azure AD app registration (client id/secret) tied
to a real tenant, which this session does not have and must not request.

No remote state backend is configured (local state only), same rationale as
`envs/aws` and `envs/gcp`.
