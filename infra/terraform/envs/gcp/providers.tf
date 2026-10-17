# The Google provider has no documented global "skip live validation" flag
# equivalent to the aws provider's skip_credentials_validation /
# skip_requesting_account_id / skip_metadata_api_check. `credentials` here
# is left to the standard `GOOGLE_APPLICATION_CREDENTIALS` / ADC resolution
# so a real deployer's normal auth just works; for a dummy/plan-only run a
# fabricated service-account JSON is pointed to via that env var (see
# envs/gcp/README.md for the result -- it does not fully avoid a live call).

provider "google" {
  project = var.project_id
  region  = var.region
}
