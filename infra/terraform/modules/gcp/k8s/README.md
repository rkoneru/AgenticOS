# gcp/k8s

Regional GKE cluster (`remove_default_node_pool = true`) with one explicit
managed node pool, workload identity enabled.

## Live-API-dependency note

`kubernetes_version` is a pinned string, not resolved via
`data "google_container_engine_versions"` ("latest" lookup), so no live GKE
version-list call is needed for `validate` or `plan`. Unlike `aws`, **the
Google provider has no documented global "skip credential validation" flag**
equivalent to `skip_credentials_validation` / `skip_requesting_account_id` /
`skip_metadata_api_check` on the `aws` provider -- so this is a real,
documented gap in what the provider itself offers. In practice, though, for
a from-scratch "everything to be created" plan with no `data` sources
anywhere in this module tree, the `google` provider never actually attempts
a live call: it lazily resolves credentials only when a request is about to
be made, and a plan that creates new resources with no existing state and
no data-source reads never makes one. A fabricated, well-formed
`GOOGLE_APPLICATION_CREDENTIALS` service-account JSON (fake key material,
real-shaped project id) is therefore enough for `terraform plan` to succeed
end to end here -- verified in `infra/terraform/envs/gcp` (see its README
for the exact command and output). This is different from `azurerm` (see `modules/azure/k8s/README.md`),
whose provider configuration step performs an OAuth2 token exchange
eagerly and fails immediately with fabricated credentials.
