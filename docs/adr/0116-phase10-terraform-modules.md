# ADR 0116: Phase 10 Terraform modules — layout, tooling, and the no-live-data-source constraint

## Status

Accepted

## Context

Phase 10 (`docs/plans/phase-10.md`, PHASE_PLAN.md Phase 10) needs Terraform
modules for AWS, GCP and Azure covering networking, managed Kubernetes,
Postgres, Redis, ClickHouse, object storage and KMS, composed into one
environment per cloud matching the control-plane's dedicated-tenant
deployment target (`services/control-plane`). Invariant from `CLAUDE.md`
("Hard stops") and this task's own instructions: `terraform apply` is never
run from an agent session, no real cloud credentials are ever requested or
used, and this is true for the entire session, not just a formality.

That constraint only has teeth if `terraform validate` and (as much as
possible) `terraform plan` can be exercised for real, with fabricated
credentials, rather than asserted. Two things stood in the way going in:
(1) no `terraform` binary was installed, and the usual install paths
(apt/yum HashiCorp repo, the shell install script) were expected to be
blocked by this environment's allowlisting outbound proxy; (2) idiomatic
Terraform for "pick the latest AMI/image/engine version" uses `data`
sources, which make real, authenticated API calls even during `plan`.

## Decision

### Tooling: real Terraform, no substitution needed

`which terraform` found nothing, and this box's apt sources carry no
`terraform` package (no HashiCorp apt repo configured, and
`ppa.launchpadcontent.net` cannot even be resolved through the proxy).
Per the task's fallback order, direct `curl` to `releases.hashicorp.com`
was tried third and tested working — contrary to the expectation that it
would likely be blocked:

```
curl -sS -o /dev/null -w '%{http_code}' https://releases.hashicorp.com/terraform/index.json
# -> 200, full 1.5MB index downloaded
```

The real `terraform_1.9.8_linux_amd64.zip` was fetched from there and
installed to `/usr/local/bin/terraform`. **No OpenTofu / Go-proxy
substitution was needed.** `go install github.com/opentofu/opentofu/cmd/tofu@latest`
was not attempted because the direct-curl path (option 3 in the task's own
ordering) worked first.

`registry.terraform.io` — the Terraform Registry used by `terraform init`
to resolve and download _provider_ plugins — **is** blocked by the agent
proxy (`CONNECT tunnel failed, response 403`, `connect_rejected`). Working
around this did not require any substitute tool: provider binaries for
`hashicorp/aws`, `hashicorp/google` and `hashicorp/azurerm` are hosted on
`releases.hashicorp.com` too (the same CDN that serves the CLI), at
`terraform-provider-<name>/<version>/terraform-provider-<name>_<version>_linux_amd64.zip`.
Each was downloaded directly, unpacked into a local filesystem-mirror
directory tree (`<mirror>/registry.terraform.io/hashicorp/<name>/<version>/linux_amd64/`),
and pointed to via a scratch `provider_installation { filesystem_mirror
{...} }` CLI config file (set only via `TF_CLI_CONFIG_FILE` in this
session's shell, never committed to the repo — a real deployer runs
ordinary `terraform init` against the real registry with no such override).

### Module layout

```
infra/terraform/modules/{aws,gcp,azure}/{networking,k8s,postgres,redis,clickhouse,object-storage,kms}/
  variables.tf  main.tf  outputs.tf  README.md
infra/terraform/envs/{aws,gcp,azure}/
  versions.tf  providers.tf  variables.tf  main.tf  outputs.tf  dummy.tfvars  README.md
```

Each module is self-contained (no cross-module `source` references); the
`envs/<cloud>` root is the only place that wires modules together, passing
one module's outputs as another's inputs (e.g. `networking`'s subnet IDs
into `k8s`/`postgres`/`redis`/`clickhouse`). This mirrors the existing
`packages/*` / `services/*` separation-of-concerns style used elsewhere in
the repo, and matches the k3s-homelab / dedicated-tenant deployment target:
one environment = one tenant's (or the home-lab's) full infrastructure,
composed from reusable per-concern modules.

Resource choices per cloud, matching `docs/plans/phase-10.md`'s list
(networking, K8s, Postgres, Redis, ClickHouse, object storage, KMS):

| Concern        | AWS                                            | GCP                                                         | Azure                                           |
| -------------- | ---------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------- |
| networking     | VPC, public/private subnets, IGW, NAT GW       | custom VPC, subnet + GKE secondary ranges, Cloud Router/NAT | VNet, AKS + delegated data subnet, NAT GW       |
| k8s            | EKS + managed node group                       | GKE (`remove_default_node_pool`) + node pool                | AKS, system-assigned identity                   |
| postgres       | RDS Postgres 16, Multi-AZ, KMS-encrypted       | Cloud SQL Postgres 16, regional HA, PITR                    | Postgres Flexible Server 16, zone-redundant     |
| redis          | ElastiCache replication group                  | Memorystore, STANDARD_HA                                    | Azure Cache for Redis, Premium                  |
| clickhouse     | self-managed on EC2 ASG (no managed service)   | self-managed on GCE MIG (no managed service)                | self-managed on Linux VMSS (no managed service) |
| object storage | S3 (versioned, SSE-KMS, public access blocked) | GCS (uniform access, CMEK, versioned)                       | Storage Account (GZRS, versioned, soft-delete)  |
| kms            | KMS key + alias                                | KMS key ring + rotating crypto key                          | Key Vault + RSA-4096 key                        |

No cloud offers managed ClickHouse, so all three `clickhouse` modules are
"self-managed compute + block storage" — explicitly out of scope: cluster
topology/replication configuration (ClickHouse Keeper, shard/replica
layout), left to `var.user_data`/`var.startup_script`/`var.custom_data`
(cloud-init) or a follow-up configuration-management step, not Terraform.
The Phase 10 Helm-chart work (a parallel effort, different worktree) is the
other option for running ClickHouse, on the `k8s` module's cluster.

### The no-live-data-source constraint

No module anywhere in this tree uses a `data` source to resolve a "most
recent" AMI/image, an available-zones list, or a "latest" engine/K8s
version. Every one of those is a plain `variable` with either a documented,
pinned default (zone names, subnet CIDRs, Postgres/Redis/K8s versions) or,
where no sane region-independent default exists (AMI/image IDs, SSH public
keys), **no default at all** — forcing the caller to supply a real value
rather than silently baking in a stale or region-wrong one. This is
documented per-module in each module's README, with the specific `data`
source that was deliberately avoided named each time.

Consequence, verified for real in this session (not merely designed for):
`terraform validate` needs zero credentials, for every module and every
env, on all three clouds. `terraform plan` against a from-scratch
("nothing exists yet") environment needs zero _data_-lookup calls on any
cloud — what each provider's own authentication step additionally requires
turned out to differ sharply by cloud:

- **AWS**: the `aws` provider block exposes `skip_credentials_validation` /
  `skip_requesting_account_id` / `skip_metadata_api_check` (wired here from
  a `dev_plan_mode` variable, default `false`, so a real deployer does not
  silently inherit skip-mode). With those on and dummy
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `terraform plan
-var-file=dummy.tfvars` in `envs/aws` **succeeds**: exit 0, "Plan: 35 to
  add, 0 to change, 0 to destroy", one expected warning (no account ID,
  because that check was explicitly skipped).
- **GCP**: the `google` provider has **no documented equivalent** global
  skip-validation flag. The expectation stated in `docs/plans/phase-10.md`
  was that `plan` would therefore fail without real credentials — that
  expectation turned out to be wrong for this specific shape of plan: a
  from-scratch create-everything plan with no `data` sources never actually
  needs the provider to make a live call, so `terraform plan
-var-file=dummy.tfvars` in `envs/gcp`, with only a fabricated
  `GOOGLE_APPLICATION_CREDENTIALS` service-account key (real JSON shape,
  fake key bytes), **also succeeds**: exit 0, "Plan: 14 to add, 0 to
  change, 0 to destroy". This does not generalize to a plan against an
  _existing_ GCP project (which would need to refresh real state).
- **Azure**: the `azurerm` provider also has no documented skip-validation
  flag, and unlike `google` it performs its OAuth2 client-credentials token
  request _eagerly_, during provider configuration, before Terraform looks
  at any resource. With fabricated `ARM_CLIENT_ID`/`ARM_CLIENT_SECRET`/
  `ARM_SUBSCRIPTION_ID`/`ARM_TENANT_ID`, `terraform plan
-var-file=dummy.tfvars` in `envs/azure` **fails**: exit 1,
  `Error: building account: could not acquire access token to parse
claims: ... AADSTS700038: ... is not a valid application identifier`.
  This is a genuine, unresolved gap: Azure `plan` cannot be verified in
  this environment without a real Azure AD app registration tied to a real
  tenant, which this session does not have and must not request.

Full commands, exact output and the reasoning above are kept in each
module's and each env's own README (`modules/*/*/README.md`,
`envs/*/README.md`) rather than duplicated in this ADR, so they stay next
to the code they describe.

## Consequences

- AWS and GCP Terraform in this repo can be `fmt`/`validate`/`plan`-checked
  in CI with zero real cloud credentials, for a from-scratch environment.
  Azure cannot; CI for Azure plan would need either a real (sandboxed, low-
  privilege) Azure AD app registration or acceptance that only
  `fmt`/`validate` run there.
- No remote state backend is configured anywhere (`backend "local"`,
  implicitly) — there is no real deployment target yet for one to point at.
  This is a deliberate placeholder, logged in `docs/NEEDS.md`, not an
  oversight: before any real `apply`, a human must add a real backend
  (S3+DynamoDB / GCS / azurerm) per cloud, with real state locking.
- The `clickhouse` modules' lack of a managed-service option is a real
  operational cost (self-managed HA/backup/upgrade burden) common to all
  three clouds, also logged in `docs/NEEDS.md`.
- `iam`/service-account/role creation is explicitly out of scope for
  `modules/aws/k8s` (`cluster_role_arn`/`node_role_arn` are inputs) and
  left to the caller elsewhere too — no `modules/*/iam` module exists yet.
