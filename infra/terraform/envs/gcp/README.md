# envs/gcp

Root composition of every `modules/gcp/*` module into one "dedicated
tenant" GCP environment (GKE + Cloud SQL Postgres 16 + Memorystore Redis +
self-managed ClickHouse on a MIG + GCS + Cloud KMS).

## Dummy-credential plan: real commands and results

```
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/fake-sa.json   # fabricated, well-formed JSON
terraform init -backend=false
terraform validate
terraform plan -var-file=dummy.tfvars
```

`terraform validate` passes with no credentials at all (pure HCL/schema
check). Unlike `aws`, the `google` provider has **no documented global
flag** that skips live credential validation -- but in practice `terraform
plan` against this from-scratch environment (nothing exists yet, no `data`
source anywhere in the module tree) succeeds too: real run in this session,
exit code 0, "Plan: 14 to add, 0 to change, 0 to destroy", with only a
fabricated `GOOGLE_APPLICATION_CREDENTIALS` service-account key (fake
private key material, well-formed JSON shape). The provider never actually
dials out, because nothing in the plan needs an existing resource read or a
data-source lookup. This is a narrower result than "the provider has a
skip-validation mode" (it does not), so a plan against an _existing_ GCP
project (refreshing real resource state) would need real credentials; a
from-scratch create plan, which is what this repo can exercise without a
cloud account, does not.

No remote state backend is configured (local state only), same rationale as
`envs/aws`.
