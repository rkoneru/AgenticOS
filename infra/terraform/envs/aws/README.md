# envs/aws

Root composition of every `modules/aws/*` module into one "dedicated
tenant" AWS environment (EKS + RDS Postgres 16 + ElastiCache Redis +
self-managed ClickHouse on an ASG + S3 + KMS), matching the dedicated-tenant
deployment target in `docs/plans/phase-10.md` / `services/control-plane`.

## Dummy-credential plan: real commands and results

Run from this directory, with:

```
export AWS_ACCESS_KEY_ID=dummy
export AWS_SECRET_ACCESS_KEY=dummy
export AWS_DEFAULT_REGION=us-east-1
terraform init -backend=false
terraform validate
terraform plan -var-file=dummy.tfvars
```

Real result captured in this session: `fmt -check`, `init -backend=false`
and `validate` all exit 0, and `plan` with `dev_plan_mode = true` (which
sets the AWS provider's `skip_credentials_validation` /
`skip_requesting_account_id` / `skip_metadata_api_check`) completes a full
plan with dummy `AWS_ACCESS_KEY_ID=dummy` / `AWS_SECRET_ACCESS_KEY=dummy` --
exit code 0, "Plan: 35 to add, 0 to change, 0 to destroy", with only a
non-fatal warning ("AWS account ID not found for provider", expected because
`skip_requesting_account_id` is on).

No remote state backend is configured (`backend "local"` implicitly) --
there is no real deployment target yet for this to point at, so this is a
deliberate placeholder, not an oversight (see `docs/NEEDS.md`).
