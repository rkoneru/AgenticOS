# AXIS Helm charts

Phase 10. See `docs/adr/0116-helm-chart-layout.md` for the layout rationale and
`docs/plans/phase-10.md` for the overall phase scope.

## Layout

```
infra/helm/
  charts/<service>/     one standalone, independently installable/lintable chart per deployable
                         process (Deployment/Service/ConfigMap/Secret/ServiceAccount/
                         NetworkPolicy/PDB/HPA)
  axis/                 the umbrella chart: Chart.yaml lists every chart above as a `file://`
                         local dependency, plus Postgres/Redis/ClickHouse as `oci://` bitnami
                         dependencies. values.yaml + six environment overlays.
```

This is the "subchart as a local dependency" layout the task description offered as an
alternative to a single monolithic umbrella tree. It was chosen over inlining every service as a
literal subdirectory of `axis/charts/` because:

- Every chart lints and templates **on its own** (`helm lint infra/helm/charts/billing`), which is
  what made the chart-by-chart x values-file-by-values-file validation matrix in this phase's exit
  bar tractable. A chart nested only inside the umbrella cannot be linted in isolation.
- Each service's own values schema, probes and NetworkPolicy rules live next to that service, not
  three directories deep inside someone else's chart.
- `helm dependency update infra/helm/axis` is the one place that resolves and locks exact
  versions (`Chart.lock`); the resolved `.tgz` archives land in `infra/helm/axis/charts/` and are
  **not** committed (see `.gitignore`) — regenerate them with that command before `helm install`/
  `helm template` against the umbrella chart. They are plain tarballs of the charts above, so
  this is reproducible and offline-safe once the first `dependency update` has run (OCI pull
  of the bitnami charts needs network access to `registry-1.docker.io`, which this repo's other
  tooling also depends on for base images).

## Services and whether they have a chart

| Service | Chart | Notes |
| --- | --- | --- |
| control-plane, risk-kernel, registry, marketplace, billing, memory, channels, eval-hub, compliance, data-governance, api-gateway | yes | each runs `node dist/main.js` (its package.json's own `dev-server`/`start` script) |
| console | yes | Next.js, `output: "standalone"`, runs `node apps/console/server.js` |
| docs-site | yes | static `make docs-build` output served by nginx (`nginxinc/nginx-unprivileged`) |
| runtime (Python) | yes, two Deployments in one chart | `run-server` (long-running HTTP worker, `runtime/scripts/run_server.py`) and `eval-runner` (per-tenant outbound-only polling worker, `runtime/scripts/eval_runner.py`, disabled by default — see that chart's `values.yaml`) |
| **approvals** | **no** | has no standalone process entrypoint at all: its only server is the dev loopback bridge *hosted inside the risk-kernel process* (`AXIS_APPROVALS_DEV_BRIDGE=1`, `services/approvals/src/dev-bridge.ts`). It ships as a second port on the `risk-kernel` chart's Deployment (`approvalsBridge.enabled`), not a separate chart. |
| **agil** | **no** | library only (`services/agil`): no `main.ts`, no `createServer`, no `dev-server` script. Per CLAUDE.md's component table it runs "behind the gateway" — linked into `api-gateway`'s process, not a standalone deployable. |
| **audit** | **no** | library only (`services/audit`, "Built as a library ... no network surface yet" per CLAUDE.md). Linked into whichever service writes audit events (control-plane, risk-kernel, billing, ...), not a standalone deployable. |
| voice | n/a, not asked for separately | `runtime/src/axis_runtime/voice` is a library inside the `runtime` package (no own entrypoint); it runs inside the run-server process, which already has a chart. |

A service with no chart is not a gap to silently paper over: if one of these three ever gets its
own network-facing entrypoint, it needs its own chart at that point, not before.

## Each service chart contains

`Deployment` (resource requests/limits, non-root + read-only-root-fs + dropped capabilities,
liveness/readiness probes against that service's own `/health` route — added in this phase where
missing, see the ADR), `Service`, `ConfigMap` (non-secret env), `Secret` *template* (values are
empty strings by default; `secret.existingSecret` points at a Secret an operator/CSI driver/CI
pipeline populates instead — nothing here is a committed real secret), `ServiceAccount`
(`automountServiceAccountToken: false`), a default-deny `NetworkPolicy` with explicit egress rules
read off each service's actual outbound calls (grep'd from `main.ts`, not guessed — see the ADR for
specifics), `PodDisruptionBudget`, and an `HorizontalPodAutoscaler` disabled by default.

## Values overlays

`values.yaml` (defaults) plus:

- `values-local.yaml` — single machine (Docker Desktop, kind/k3d): 1 replica everywhere, PDBs off,
  small in-cluster Postgres/Redis.
- `values-k3s-homelab.yaml` — a small persistent bare-metal/NUC cluster: same low footprint as
  local but assumes the cluster outlives any one `helm upgrade`.
- `values-aws.yaml` / `values-gcp.yaml` / `values-azure.yaml` — disable the in-cluster
  Postgres/Redis/ClickHouse subcharts, turn HPAs on, add IRSA / Workload Identity / Azure AD
  Workload Identity annotation placeholders, and point at a managed database (see "Swapping in a
  managed service" below). The managed resources themselves (RDS/Cloud SQL/Azure Database,
  ElastiCache/Memorystore/Azure Cache, EKS/GKE/AKS) are Terraform's job
  (`infra/terraform/{aws,gcp,azure}`, the phase's other workstream), not this chart's.
- `values-dedicated.yaml` — one full release per tenant, its own namespace, its own
  (in-cluster, tenant-sized) Postgres, and same-namespace-only NetworkPolicy ingress. This matches
  the control plane's existing `dedicated_db` / `single_tenant_vpc` isolation tiers
  (`services/control-plane/src/types.ts`, `src/tenancy.ts`) — those tiers already exist in code and
  are enforced at the database-pool level; this values file is the Phase 10 piece that actually
  deploys a tenant that way.

### Swapping in a managed service

Every service chart's database URL lives in `secret.data.<SERVICE>_DATABASE_URL` (or `CP_PG_URL` /
`AXIS_AUDIT_PG_URL` for control-plane/risk-kernel). To move off the in-cluster bitnami Postgres:

1. Disable the subchart: `postgresql.enabled: false` (done for you in the cloud value files).
2. Populate the managed connection string into a Secret by whatever mechanism your cluster uses
   (External Secrets Operator, the cloud provider's Secrets/Parameter Store CSI driver, or a
   one-time `kubectl create secret` during provisioning).
3. Point the chart at it: `<service>.secret.existingSecret: "<that-secret-name>"` instead of
   `secret.data`.

ClickHouse stays `enabled: false` even on the cloud value files: no AXIS service reads a
`CLICKHOUSE_*` environment variable today (checked by grep across `services/*/src`,
`apps/*/src`, `runtime/src` — zero hits), so there is nothing yet for a ClickHouse endpoint to be
wired into. Flip it on once that wiring exists; until then it is dead weight, in-cluster or managed.

## Validation performed

- `helm lint` on every one of the 14 service charts, 3 variants each (defaults, forced single
  replica, forced autoscaling) — 42/42 pass.
- `helm template` on every one of the 14 service charts against every one of the 7 umbrella values
  files, piped through `kubeconform -strict` — 98/98 render and validate as real Kubernetes
  objects.
- The full umbrella chart (`helm dependency update` then `helm template`) against each of the 7
  values files (including "every AXIS service and both bitnami subcharts enabled") — every run is
  0 invalid / 0 errors under `kubeconform -strict`.
- `axis/billing`, `axis/memory`, `axis/registry`, `axis/channels`, `axis/compliance`,
  `axis/control-plane`, `axis/data-governance`, `axis/eval-hub`, `axis/marketplace`,
  `axis/risk-kernel`, `axis/api-gateway`, `axis/console`, `axis/docs-site` and `axis/runtime`
  Docker images were actually built from their Dockerfiles and run with `docker run`; each
  service's `/health` (or `/api/health`) endpoint was curled and returned `{"status":"ok"}`. Three
  real bugs were found and fixed this way (not found by `helm lint`/`helm template`, which cannot
  catch them): the console's standalone Next.js output needs its original directory nesting to
  keep pnpm's symlinks valid, the Python runtime needs `uv sync --no-editable` so
  `axis_runtime` is actually installed rather than `.pth`-redirected to a source tree the final
  image doesn't contain, and the docs site's build needs `docs/` in the Docker build context.

Helm (`v3.16`, built with `go install helm.sh/helm/v3/cmd/helm`, since `get.helm.sh`'s installer
script is not reachable from this environment) and `kubeconform` (`go install
github.com/yannh/kubeconform/cmd/kubeconform`) were the validation tools; no cloud credentials or
live cluster were used or required for any of the above.

## Known gaps (see `docs/NEEDS.md` for the numbered entries)

- `api-gateway`'s standalone process refuses to bind anything but a loopback address
  (`GW_HOST`), so its chart's `Service` cannot actually forward real cluster traffic to it yet —
  only in-pod exec probes work. Fixing this is a gateway change (production wiring), not a chart
  change.
- The Risk Kernel has no HTTP surface (gRPC only) and no gRPC health-checking-protocol service
  wired up, so its chart's probes are a plain TCP accept check, not a real readiness signal.
- The Eval Hub runner (`runtime`'s `eval-runner` Deployment) has no network-facing surface of any
  kind (it only polls outbound), so it has no liveness/readiness probe at all — only Kubernetes'
  restart-on-exit applies. It is also one release per tenant in production (see `values.yaml`),
  which this chart does not template out as a list; a real multi-tenant rollout needs either N
  `helm install`s or a small wrapper this phase did not build.
- This chart has not yet been installed against a real cluster (that is `infra/helm` validation
  only); bringing up a local k3d cluster and installing it for real is a separate Phase 10
  workstream (`phase10-cluster` in `docs/plans/phase-10.md`).
