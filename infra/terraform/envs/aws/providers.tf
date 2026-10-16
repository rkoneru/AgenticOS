# Dev/plan-only provider configuration. `skip_credentials_validation`,
# `skip_requesting_account_id` and `skip_metadata_api_check` let
# `terraform plan` run against dummy credentials without an STS call --
# see envs/aws/README.md for exactly what this does and does not avoid.
# These flags are sourced from a variable (default false) rather than
# hard-coded true, so a real deployment (run by a human, never by this
# session) does not silently keep them on.

provider "aws" {
  region = var.region

  skip_credentials_validation = var.dev_plan_mode
  skip_requesting_account_id  = var.dev_plan_mode
  skip_metadata_api_check     = var.dev_plan_mode
}
