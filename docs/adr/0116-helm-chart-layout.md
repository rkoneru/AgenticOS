# ADR 0116: Helm chart layout — per-service charts as local dependencies of one umbrella chart

Status: accepted. Phase 10 (`docs/plans/phase-10.md`, workstream `phase10-helm`).

## Decision

`infra/helm/charts/<service>/` holds one standalone chart per deployable process. `infra/helm/axis/`
is an umbrella chart whose `Chart.yaml` lists every one of those as a `file://../charts/<service>`
dependency, each gated by a `<service>.enabled` condition, plus Postgres/Redis/ClickHouse as
`oci://registry-1.docker.io/bitnamicharts/*` dependencies (bitnami moved off a classic Helm repo to
OCI-only distribution; `charts.bitnami.com` itself is not reachable from this environment's egress
allowlist, but `registry-1.docker.io` is — the same host Docker image pulls already depend on).

This was the explicit either/or the phase's task description offered ("each service as a subchart,
or `infra/helm/charts/<service>/` referenced as a local dependency — pick one and document it").
Taken: the local-dependency layout.

## Why

The exit bar for this phase is `helm lint` and `helm template` across **every chart times every
values file**. A chart that only exists nested inside the umbrella's own `templates/`/`charts/`
tree cannot be linted or templated on its own — `helm lint infra/helm/charts/billing` would not be
a meaningful command if `billing`'s Deployment template lived at
`infra/helm/axis/templates/billing-deployment.yaml` instead. The local-dependency layout makes the
granular, per-chart validation the exit bar actually asks for possible in the first place, at the
cost of one extra `helm dependency update` step before installing or templating the umbrella.

A secondary reason: 14 services share almost the same shape (Deployment + Service + ConfigMap +
Secret + ServiceAccount + NetworkPolicy + PDB + HPA), but each one's probe path, port, secret keys
and NetworkPolicy egress rules differ. A single umbrella template tree would need `{{- if eq
.Chart.Name "billing" }}`-style branching to express those per-service differences, or a library
chart with enough indirection to make the per-service NetworkPolicy rules (the part a reviewer most
needs to read plainly) hard to find. Separate charts keep each service's actual configuration
next to that service, in its own `values.yaml`, lintable and readable on its own.

## What did not become its own chart, and why

Checked against the actual code, not assumed from the service list in the phase brief:

- **`services/approvals`** has no standalone process entrypoint (no `main.ts`, no `dev-server`
  script). Its only server (`src/dev-bridge.ts`'s `createDevServer`) is started *inside the
  risk-kernel process* when `AXIS_APPROVALS_DEV_BRIDGE=1`
  (`services/risk-kernel/src/main.ts`, `createDevBridge(...)`), matching CLAUDE.md's own
  component-table description ("wired to the kernel + runtime end to end via a dev-only loopback
  bridge"). It ships as a second container port on the `risk-kernel` chart
  (`approvalsBridge.enabled`), not a separate Deployment.
- **`services/agil`** and **`services/audit`** are libraries with no `createServer`/`listen` call
  anywhere in their `src/` (checked by grep), matching their CLAUDE.md rows ("behind the gateway",
  "Built as a library ... no network surface yet"). They have no chart because they have nothing
  to deploy independently; they are linked into whichever process imports them
  (`api-gateway`, `control-plane`, `risk-kernel`, `billing`, ...).
- **`runtime/`'s voice pipeline** (`runtime/src/axis_runtime/voice`) is a library inside the
  `runtime` package with no entrypoint of its own; it runs inside the run-server process, which
  already has a chart (the `runServer` Deployment in `infra/helm/charts/runtime`).

## Health probes added, not faked

Before this phase, none of the TypeScript dev-server HTTP surfaces (billing, channels, compliance,
control-plane, data-governance, eval-hub, marketplace, memory, registry) nor the Python run server
had a `/health` route, and three of them (`api-gateway`'s standalone server, and every
`http.createServer`'s `listenLoopback`) hardcoded a `127.0.0.1`/loopback bind with no way to listen
on a container's pod IP. Per this phase's own instruction ("add one via a minimal ADR'd change if
genuinely missing, don't fake a probe path that doesn't exist"):

- Added an unauthenticated `GET /health` returning `{"status":"ok"}` to each of those nine
  TypeScript HTTP servers and to the Python run server, ahead of any auth/routing logic, touching
  nothing else in each file.
- Added an `AXIS_BIND_HOST` environment override (default unchanged: `127.0.0.1`) to each
  `listenLoopback`/gRPC `listen()` call so a container can bind `0.0.0.0` without changing any
  existing test's behavior (every existing caller leaves `AXIS_BIND_HOST` unset).
- Added `GET /api/health` to the console (a plain Next.js route handler) and relied on
  `docs-site`'s own nginx config for its `/health` (a static 200, since there is nothing dynamic to
  check).
- Did **not** add a fix for `api-gateway`: its `configFromEnv()` deliberately refuses any
  `GW_HOST` other than a loopback address, by design (no TLS, static per-tenant token files — see
  `apps/api-gateway/src/standalone.ts`'s own comment). Patching that open was out of scope for a
  chart-layout phase and would change a documented security posture choice without review. Its
  chart therefore uses an `exec` probe (a tiny bundled script that curls `127.0.0.1` from inside
  the container) instead of `httpGet`, and its `Service` is documented (chart `NOTES.txt`,
  `infra/helm/README.md`) as not actually reachable from other pods yet.
- The Risk Kernel is gRPC-only with no HTTP surface and no gRPC health-checking-protocol service
  implemented; its chart's probes are a plain `tcpSocket` accept check — proof the listener is up,
  not that it answers correctly. Logged as a real gap rather than left unstated (`docs/NEEDS.md`).

## NetworkPolicy egress

Each service's `main.ts` was grepped for its actual outbound calls (`new pg.Pool`, `http://`/
`https://` literals, `fetch(`) rather than guessed. Every one of the nine Postgres-backed dev
servers plus control-plane and risk-kernel only connects to Postgres directly; none of them call
out to another AXIS service over the network (the dev/e2e composition shares one Postgres instead
of service-to-service HTTP calls — matching CLAUDE.md's "dev composition", "loopback dev HTTP"
language throughout the component table). `api-gateway` additionally calls the run service and the
approvals bridge by URL (`GW_RUN_SERVICE_URL`, `GW_APPROVALS_URL`); the `runtime` chart calls out to
risk-kernel (gRPC), control-plane, billing, memory and eval-hub. Each chart's
`networkPolicy.extraEgress` encodes exactly these and nothing more; everything else is denied by
default (default-deny plus DNS is the only unconditional egress rule).

A bug was found and fixed while building the `values-dedicated.yaml` overlay: the generic ingress
rule all 14 charts started from used `from: [{namespaceSelector: {}}]`, which in Kubernetes
NetworkPolicy semantics means "pods in **every** namespace" — the opposite of the intended
same-namespace default-allow, and a real over-permissive-by-default bug across every chart, not
specific to the dedicated profile. Fixed to `from: [{podSelector: {}}]` (Kubernetes' own
same-namespace default when `namespaceSelector` is omitted) in all 14 charts; cross-namespace
ingress (an Ingress controller in its own namespace, for instance) goes through each chart's
`networkPolicy.extraIngress` instead.

## Validation

`helm` was not installed in this environment. `get.helm.sh`'s installer script is not reachable
through this session's egress proxy (confirmed: a direct `curl` to it is refused the same way
`get.k3s.io` is, per this phase's own environment notes). The Go toolchain and `proxy.golang.org`
are both reachable, so `go install helm.sh/helm/v3/cmd/helm@v3.16.4` built a working `helm` binary;
`go install github.com/yannh/kubeconform/cmd/kubeconform@v0.6.7` likewise built `kubeconform`. Both
tools were therefore available for real `helm lint` / `helm template` + `kubeconform -strict`
validation — not a fallback tier. See `infra/helm/README.md`'s "Validation performed" section for
the exact pass counts, and the same section for the three real Dockerfile bugs this validation
found (and fixed) that `helm lint`/`helm template` alone could not catch, because `docker build` +
`docker run` + curling each `/health` endpoint was also run for every image.
