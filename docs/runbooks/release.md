# Release process and versioning

Scope: how an AXIS platform release is cut, versioned, built, and rolled out.
This is about releasing **the platform itself** — not to be confused with
blueprint versioning (`docs/adr/0030-blueprint-registry.md`), which is a
separate, tenant-facing concept with its own signed-version/semver scheme
that this runbook deliberately mirrors for consistency.

## Versioning scheme

- **Platform release version**: strict semver (`MAJOR.MINOR.PATCH`), one
  version for the whole monorepo release — not per-package. Tag format:
  `v<major>.<minor>.<patch>` (e.g. `v0.10.0` for the Phase 10 exit).
  - MAJOR: a frozen-contract break (gRPC/OpenAPI/ABL schema/DB schema) that
    is not purely additive. Per the working rules, this needs an ADR before
    the break lands, not just before the release.
  - MINOR: a new capability, a new service, a new Helm chart, a new
    Terraform module, an additive contract change (new optional field, new
    operation) — anything released under an ADR that doesn't break an
    existing consumer.
  - PATCH: bug fixes, dependency bumps, doc/runbook changes, chart/values
    tweaks that don't change a contract.
- **Component status labels** (`Concept / Designed / Prototype / Built /
Deployed`, per CLAUDE.md invariant 6) are independent of the release
  version — a MINOR release can still carry components at `Prototype`.
  The release notes must say so; a version bump never implies every
  component crossed a maturity line.
- **Container image tags**: `ghcr.io/axis/<service>:<platform-version>`
  (immutable, never retagged) plus a floating `:latest` for local/dev
  convenience only — Helm `values-*.yaml` for anything beyond `local`
  always pin the exact version tag, never `:latest`.
- **Helm chart versions**: each chart's `Chart.yaml` `version` follows the
  same semver discipline independently (a chart-only fix is a chart PATCH
  without a new platform release), but `appVersion` always tracks the
  platform version of the image it ships.
- **Contracts freeze**: `packages/contracts/FREEZE.json` is regenerated
  (`make freeze`) only inside a release that an ADR says is allowed to touch
  it (ADR 0007). A release that changes `FREEZE.json` is at minimum MINOR
  (additive) or MAJOR (breaking); never silently part of a PATCH.

## Branching and tagging

- Development happens on short-lived feature/phase branches merged into the
  trunk (`main` once this repo has one; this session's work so far has
  lived on a single long-running development branch per its working
  instructions).
- A release is cut by tagging the trunk commit that passed the full gate
  below: `git tag -s v0.10.0 -m "..."` (sign if a real signing key exists;
  this environment has none — log the gap in `docs/NEEDS.md` rather than
  faking a signature) and pushing the tag.
- `CHANGELOG.md` gets a release-dated section added in the same commit the
  tag points at, following the existing per-phase-exit entry style already
  in this file.

## Release gate (what must be true before a tag is cut)

All of the following, run fresh on the commit being tagged (same bar as
every phase-exit sweep this project has used throughout):

1. `pnpm build && pnpm lint && pnpm typecheck`
2. `pnpm exec turbo run cov --force --concurrency=2` (coverage floors:
   95% core packages, 85% elsewhere, per CLAUDE.md)
3. `make policy-test contracts-lint compliance-check threatmodel-check
redteam-lint`
4. Every `make e2e-phaseN` target (core through 9) and `make
e2e-compliance e2e-governance console-e2e docs-build evals redteam
redteam-selfcheck chaos`
5. `make dr-drill` (needs PostgreSQL binaries + root; re-run fresh, not a
   stale committed result, for an actual release — a phase-exit sweep may
   accept the committed result per NEEDS #420, but a release tag should
   not)
6. `uv run ruff check . && uv run ruff format --check . && uv run mypy
runtime/src sdk/python/src && uv run pytest runtime sdk/python -q`
7. `helm lint` + `helm template` (+ `kubeconform -strict` where available)
   across every chart x every values file (`infra/helm/`)
8. `terraform fmt -check -recursive && terraform validate` for every
   Terraform module and env (`infra/terraform/`) — `plan` is informational
   for a platform release (nothing here deploys to a real cloud account
   yet; see `docs/NEEDS.md` #500-505)
9. `docs/FINAL_REPORT.md` and the `CLAUDE.md` component table are current
   as of the tagged commit — a release is never tagged against a stale
   status table

A release is refused (not cut) if any step is red. "Mostly green" is not a
release gate — this mirrors the fail-closed invariant applied to the
project's own delivery process, not just to runtime requests.

## Build and publish

1. For each service with a Dockerfile (`services/*/Dockerfile`,
   `runtime/Dockerfile`, `apps/api-gateway/Dockerfile`,
   `apps/console/Dockerfile`, `apps/docs-site/Dockerfile`): `docker build`
   with the release version as the tag, using the per-Dockerfile
   `--build-arg` pattern documented in `docs/runbooks/local-cluster.md` for
   any build-time package fetches.
2. Publish images to a real registry — **publishing packages/images
   publicly is a hard stop** per CLAUDE.md; this step pauses for the user
   in any environment, including this one, until a registry and
   credentials are explicitly provided.
3. `helm package` each chart (or the umbrella) at its `Chart.yaml` version
   and publish to a chart repository — same hard stop as above for public
   publication; an internal/private registry the user has already
   provisioned is fine once named.

## Rollout

- **local / k3s-homelab**: `helm upgrade --install axis infra/helm/axis -f
infra/helm/axis/values-<profile>.yaml` directly; see
  `docs/runbooks/local-cluster.md` for the local k3d walkthrough this
  phase verified for real.
- **aws / gcp / azure**: `terraform plan` (never `apply` without the user
  present and real credentials provisioned — hard stop) against
  `infra/terraform/envs/<cloud>` to stand up the managed infra, then the
  same `helm upgrade --install` against the resulting cluster with
  `values-<cloud>.yaml`.
- **dedicated**: a per-tenant namespace/cluster using `values-dedicated.yaml`,
  matching the control-plane's existing dedicated-tenant routing/DB
  isolation (`services/control-plane`).
- Rollback: `helm rollback axis <previous-release-number>` (Helm keeps
  release history); for a contract-breaking MAJOR release, rollback also
  requires restoring the prior `FREEZE.json` and re-deploying matching
  service images — never roll back a schema migration automatically
  without a human reviewing the down-migration, since migrations in this
  repo are additive-forward by convention (see `packages/db/migrations/`).

## Post-release

- Open a tracking note in `docs/NEEDS.md` for anything the release gate
  revealed but didn't block on (flagged, not silently dropped).
- Update the `CLAUDE.md` component-status table for every component whose
  evidence changed in this release.
- If the release was cut from an automated loop/session rather than an
  interactive one, the session says so plainly in the release notes rather
  than implying a human reviewed it.
