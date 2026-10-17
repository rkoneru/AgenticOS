# Running AXIS on a real local Kubernetes cluster (k3d)

Phase 10, workstream `phase10-cluster`. This is the honest record of what was actually run
against a real k3d cluster in this sandboxed dev environment, not a design document: every
command here was executed for real; every gap below was found live, not guessed. See
`docs/plans/phase-10.md` for the phase's overall scope and `infra/helm/README.md` /
`docs/adr/0116-helm-chart-layout.md` for the chart layout this builds on.

## What was achieved

- A real k3d (k3s-in-Docker) single-node cluster, created and torn down for real.
- Real container images built from this repo's own Dockerfiles for `risk-kernel`,
  `control-plane` and the Python `runtime` (run-server), imported into the cluster (no external
  registry).
- `helm install`/`helm upgrade` of a **subset** of the `infra/helm/axis` umbrella chart (Postgres
  + risk-kernel + control-plane + runtime; the other 11 AXIS service charts disabled — see
  `infra/helm/axis/values-local-cluster-subset.yaml`) against the real cluster's API server.
- **Running/Ready in the real cluster**: Postgres (`axis-postgresql-0`, bitnami chart), the real
  Risk Kernel pod (`axis-risk-kernel-*`), and the real Python runtime run-server pod
  (`axis-runtime-run-server-*`). `control-plane` does **not** reach Ready — see Known gaps.
- A **real gRPC `Evaluate` call**, from a pod inside the cluster, to the real Risk Kernel pod's
  ClusterIP, gated by the real compiled policy bundle (`baseline-deny` + `phi-redaction`),
  producing a real `ALLOW` decision for a read tool call and a real default-`DENY` decision for
  an unlisted write tool call — and in both cases a real, hash-chained row landing in the real
  Postgres pod's `audit_events` table (verified by querying Postgres directly for the exact
  `trace_id`). This is the Phase-2 core-loop decision path (ABL → runtime → Risk Kernel over gRPC
  → Postgres audit), exercised against the live cluster, not the ephemeral-process harness
  `make e2e-core` normally uses.
- The cluster was torn down cleanly at the end (`k3d cluster delete`); nothing was left running.

## What was *not* achieved (be precise about this)

- `control-plane` does not reach `Ready`: its image is missing a `policies/control-plane/`
  directory its `main.ts` expects at a fixed path (NEEDS #514). Not fixed in this pass.
- The other 11 AXIS service charts (registry, marketplace, billing, memory, channels, eval-hub,
  compliance, data-governance, api-gateway, console, docs-site) were not built, imported or
  installed in this pass — disabled via the subset values file, not attempted-and-failed.
- `make e2e-core` itself was **not** retargeted at the live cluster. The existing harness
  (`e2e/test_phase2_core_loop.py`) spawns its own ephemeral risk-kernel subprocess and throwaway
  Postgres; it has no env-var override to point at a remote host:port instead, and retrofitting
  that in the time available was impractical (see "Why a new smoke script" below). A small new
  smoke script (checked into this session, kept under `docs/runbooks/` as the one described here;
  the actual script content is reproduced below rather than committed as a repo file, since it's
  a one-off verification artifact, not a maintained test) was written and run instead, driving the
  exact same real path.
- Redis was disabled for this pass (not on the Phase-2 core-loop decision path).
- ClickHouse was never enabled (per `infra/helm/README.md`: no AXIS service reads a `CLICKHOUSE_*`
  env var yet).

## Environment facts worth knowing before you try this again

- `dockerd` must be running (`docker info`) before any of this.
- Outbound network from this sandbox is allowlisted; `get.k3s.io`, `get.helm.sh`, bare
  `github.com` and `ghcr.io` are **not** reachable. `registry-1.docker.io` (Docker Hub, including
  OCI chart pulls), `proxy.golang.org`, `registry.npmjs.org` and `pypi.org` **are**.
- `helm` and `kubeconform` were already built via `go install` by prior Phase 10 work
  (`~/go/bin`); `k3d` was not — see "Installing k3d" below.
- Disk is a hard, shared budget (around 20 GB free when this session started). `docker system
  prune -af`/`docker builder prune -af` between build batches, and build/import images one at a
  time, not in parallel.
- Docker Hub pulls can hit `429 Too Many Requests` from the shared proxy IP; retry with backoff.

## Step by step

### 1. Install `k3d` (not available via its own installer here)

`get.k3d.io`'s shell installer is unreachable; `go install` works (`proxy.golang.org` is
allowlisted):

```bash
export PATH="$PATH:$HOME/go/bin"
go install github.com/k3d-io/k3d/v5@latest
```

### 2. Build a local `k3d-tools` image (the stock one is on `ghcr.io`, which is blocked)

k3d unconditionally needs a "tools" helper image (`ghcr.io/k3d-io/k3d-tools`) for environment
bootstrapping and image import, and `ghcr.io` is not reachable from this sandbox. It has its own
small Go module under `tools/` in the k3d source tree that builds without needing `apk`/`make`:

```bash
git clone --depth 1 --branch v5.8.3 https://github.com/k3d-io/k3d.git /tmp/k3dsrc
cat > /tmp/k3dsrc/tools/Dockerfile.local <<'EOF'
FROM golang:1.22.4-alpine3.20 AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
RUN go build -o bin/k3d-tools .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/bin/k3d-tools .
ENTRYPOINT [ "/app/k3d-tools"]
EOF
# proxy.golang.org is MITM'd by this sandbox's egress proxy same as everything else outside the
# narrow no-proxy allowlist, so the Go module fetch needs the proxy's CA trusted — see the CA
# pattern in step 3; the same --build-context + --network=host trick applies here too.
cp /root/.ccr/ca-bundle.crt /tmp/k3dsrc/tools/ca-bundle.crt
cd /tmp/k3dsrc/tools
docker build --network=host -f Dockerfile.local -t k3d-tools-local:v5.8.3 .
```

(`k3d-proxy`, the optional load-balancer, is also on `ghcr.io`; avoided entirely with `--no-lb`
at cluster-create time, since this is a single-node local cluster with no need for one.)

### 3. Build the real AXIS images, with CA trust threaded through for this sandbox's proxy

A `docker build` step that fetches packages (npm/pnpm/pip) needs `--network=host` (so it shares
the host's network namespace and its proxy env vars) **and** needs to trust this sandbox's
TLS-intercepting egress proxy's CA, because most of what a build needs (`registry.npmjs.org`,
`proxy.golang.org`, etc.) is MITM'd here even though it is also in the standard `NO_PROXY` list.
`services/risk-kernel/Dockerfile`, `services/control-plane/Dockerfile` and `runtime/Dockerfile`
now carry an ARG-gated pattern for this that is a no-op for anyone building without it:

```dockerfile
ARG CI_PROXY_CA_BASE=ca-empty
FROM scratch AS ca-empty
FROM ${CI_PROXY_CA_BASE} AS ca-src

FROM node:22-alpine AS builder   # (or python:3.12-slim for the runtime image)
COPY --from=ca-src ca-bundle.cr[t] /tmp/
RUN if [ -f /tmp/ca-bundle.crt ]; then cp /tmp/ca-bundle.crt /tmp/ci-proxy-ca.pem; fi
ENV NODE_EXTRA_CA_CERTS=/tmp/ci-proxy-ca.pem   # or: append to /etc/ssl/certs/ca-certificates.crt
...                                             #     + SSL_CERT_FILE/PIP_CERT for Python
```

Build with the CA context supplied (only needed inside this kind of sandbox):

```bash
cd <repo root>
docker build --network=host \
  --build-context ciproxyca=/root/.ccr --build-arg CI_PROXY_CA_BASE=ciproxyca \
  -f services/risk-kernel/Dockerfile -t axis/risk-kernel:dev .
docker build --network=host \
  --build-context ciproxyca=/root/.ccr --build-arg CI_PROXY_CA_BASE=ciproxyca \
  -f services/control-plane/Dockerfile -t axis/control-plane:dev .
docker build --network=host \
  --build-context ciproxyca=/root/.ccr --build-arg CI_PROXY_CA_BASE=ciproxyca \
  -f runtime/Dockerfile -t axis/runtime:dev .
```

On a normal host with real internet access, omit all three (`--build-context`, `--build-arg`,
`--network=host`) and these Dockerfiles build exactly as before.

### 4. Create the cluster, with two more sandbox-specific fixes

```bash
export PATH="$PATH:$HOME/go/bin"
export K3D_IMAGE_TOOLS="docker.io/library/k3d-tools-local:v5.8.3"
k3d cluster create axis-local \
  --servers 1 --agents 0 \
  --k3s-arg "--disable=traefik@server:0" \
  --k3s-arg "--disable=servicelb@server:0" \
  --k3s-arg "--snapshotter=native@server:0" \
  --k3s-arg "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@server:0" \
  --volume /tmp/containerd-config.toml.tmpl:/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl@server:0 \
  --no-lb \
  --image rancher/k3s:v1.32.5-k3s1 \
  --wait --timeout 180s
```

Two of these flags only exist because of this sandbox's nested virtualization:

- `--snapshotter=native` — tried first because containerd's default `overlayfs` snapshotter
  inside a container whose own root is already `overlayfs` (`docker info | grep "Storage
  Driver"`) is a classic "overlay-on-overlay" failure mode. It turned out **not** to be the actual
  cause of the real blocker below, but is harmless and was left in.
- `--kubelet-arg=eviction-hard=...<1%` — **required**. `cAdvisor` reports `invalid capacity 0 on
  image filesystem` in this nested environment, so kubelet's default disk-pressure eviction
  thresholds immediately taint the node `disk-pressure:NoSchedule` regardless of real free space,
  wedging every pod. See NEEDS #512.

The `--volume ... config.toml.tmpl` mount is the fix for the **actual** structural blocker found
in this session (see "The real blocker" below) — write its content first:

```bash
cat > /tmp/containerd-config.toml.tmpl <<'EOF'
version = 3
root = "/var/lib/rancher/k3s/agent/containerd"
state = "/run/k3s/containerd"

[grpc]
  address = "/run/k3s/containerd/containerd.sock"

[plugins.'io.containerd.internal.v1.opt']
  path = "/var/lib/rancher/k3s/agent/containerd"

[plugins.'io.containerd.grpc.v1.cri']
  stream_server_address = "127.0.0.1"
  stream_server_port = "10010"

[plugins.'io.containerd.cri.v1.runtime']
  enable_selinux = false
  enable_unprivileged_ports = true
  enable_unprivileged_icmp = true
  device_ownership_from_security_context = false
  restrict_oom_score_adj = true

[plugins.'io.containerd.cri.v1.images']
  snapshotter = "native"
  disable_snapshot_annotations = true

[plugins.'io.containerd.cri.v1.images'.pinned_images]
  sandbox = "rancher/mirrored-pause:3.6"

[plugins.'io.containerd.cri.v1.runtime'.cni]
  bin_dir = "/var/lib/rancher/k3s/data/cni"
  conf_dir = "/var/lib/rancher/k3s/agent/etc/cni/net.d"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
  SystemdCgroup = false

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runhcs-wcow-process]
  runtime_type = "io.containerd.runhcs.v1"

[plugins.'io.containerd.cri.v1.images'.registry]
  config_path = "/var/lib/rancher/k3s/agent/etc/containerd/certs.d"
EOF
```

#### The real blocker, and how it was found

Every pod's sandbox (the "pause" container) failed with the exact same opaque error:

```
failed to create containerd task: failed to create shim task: OCI runtime create failed:
runc create failed: unable to start container process: can't get final child's PID from pipe: EOF
```

This reproduced even for a `hostNetwork: true` pod and an explicit `crictl runp` with
`seccomp.profile_type: Unconfined`, ruling out CNI/network-namespace setup and seccomp as the
cause. Racing a `find` loop against `crictl runp` to catch the OCI bundle before cleanup, then
running `runc --debug create` by hand against that same bundle, surfaced the real error buried in
runc's debug log:

```
nsexec[...]: update /proc/self/oom_score_adj to '-998'
nsexec[...]: failed to update /proc/self/oom_score_adj: Permission denied
```

Writing a *more negative* `oom_score_adj` than a process's enclosing container already has is
blocked in this nested sandbox (the same restriction that produces k3s's own non-fatal
`"Failed to ensure state" ... failed to apply oom score -999 ... permission denied` warning in its
logs). containerd's CRI plugin has a config flag for exactly this situation —
`restrict_oom_score_adj = true` — which clamps the OOM score adjustment it asks for to what the
*containerd process's own* current value allows, instead of the CRI-computed value unconditionally.
Setting it (via the `config.toml.tmpl` override, since k3s regenerates `config.toml` from this
template on every start) fixed every pod sandbox, no further workaround needed.

### 5. Import images into the cluster (not via `k3d image import` — see NEEDS #520)

```bash
docker save rancher/mirrored-pause:3.6 rancher/mirrored-coredns-coredns:1.12.1 \
  rancher/local-path-provisioner:v0.0.31 rancher/mirrored-metrics-server:v0.7.2 \
  rancher/mirrored-library-busybox:1.36.1 bitnami/postgresql:latest \
  axis/risk-kernel:dev axis/control-plane:dev axis/runtime:dev \
  -o /tmp/all.tar
docker cp /tmp/all.tar k3d-axis-local-server-0:/tmp/all.tar
docker exec k3d-axis-local-server-0 ctr -n k8s.io images import /tmp/all.tar
docker exec k3d-axis-local-server-0 rm -f /tmp/all.tar
```

`k3d image import` itself failed in this environment with
`ctr: rpc error: code = NotFound desc = content digest ...: not found` even though the
image import generally succeeded on the host side; `docker save` + `ctr -n k8s.io images import`
run directly inside the node container was used throughout instead and worked reliably every
time. The five `rancher/*` images above are k3s's own bootstrap images (pause, CoreDNS,
local-path-provisioner, metrics-server, busybox) — pull them with `docker pull` (with retries for
Docker Hub's `429`s) before saving.

`bitnami/postgresql`'s chart-pinned tag (`17.2.0-debian-12-r1`) is no longer pullable (bitnami
retention policy change — see NEEDS #519); `docker pull bitnami/postgresql:latest` and override
`postgresql.image.tag: latest` instead (done in `values-local-cluster-subset.yaml`).

### 6. `helm install`

```bash
export PATH="$PATH:$HOME/go/bin"
export KUBECONFIG=/tmp/kubeconfig-axis.yaml
k3d kubeconfig get axis-local > $KUBECONFIG
cd infra/helm/axis
helm dependency update .
helm install axis . \
  -f values.yaml -f values-local.yaml -f values-local-cluster-subset.yaml \
  --namespace axis --create-namespace --timeout 10m --wait=false
```

`values-local-cluster-subset.yaml` (new, this session) disables every AXIS chart except
control-plane, risk-kernel and runtime (real images were only built for these three), disables
Redis, overrides the Postgres image tag (see above), and — because this is a real cluster, not
`helm template` — wires real secrets for the services that actually got deployed: a real
compiled policy bundle + token table for risk-kernel (added `tokens.secretName`, a new chart
input — see NEEDS #517), a real Postgres URL for control-plane, and a real `RUNSERVER_CONFIG` for
the runtime run-server. See that file for the exact values and NEEDS #514–#519 for the real bugs
this surfaced and (mostly) got fixed.

There is **no `kubectl` binary** available directly in this sandbox; every `kubectl` invocation
in this runbook goes through the k3s node container, which ships its own:

```bash
docker exec -i k3d-axis-local-server-0 kubectl "$@"
```

### 7. Apply the DB migration and seed a tenant (also via a one-off Job, same reason)

```bash
# Build a tiny node:22-alpine image that just runs `node dist/cli.js` (packages/db's compiled
# migration CLI) with the same CA-trust pattern as step 3's Dockerfiles.
docker build --network=host --build-context ciproxyca=/root/.ccr --build-arg CI_PROXY_CA_BASE=ciproxyca \
  -f /tmp/migrate.Dockerfile -t axis/db-migrate:dev .
# import it the same way as step 5, then:
kubectl apply -f migrate-job.yaml   # DATABASE_URL = postgres superuser, NOT the 'axis' owner role
                                     # (CREATE EXTENSION needs superuser)
kubectl apply -f tenant-job.yaml    # INSERT INTO tenants (...)
```

### 8. Drive the real gRPC path and verify the real audit row

A one-off Python script (reproduced here, not committed as a repo file — it is a one-time
verification artifact, not a maintained test) run **inside the cluster**, using the real
`axis_runtime.gate.GrpcGateClient` already present in the `axis/runtime:dev` image, against the
real risk-kernel pod's ClusterIP:

```python
import asyncio, secrets, sys
from axis_runtime.gate import ActorType, EnforcementPoint, EvaluateRequest, GrpcGateClient
from axis_runtime.process import new_pid

TENANT = "c1057100-0000-4000-8000-000000000001"
TOKEN = "cluster-e2e-44a38b113b56862a"
KERNEL_TARGET = "axis-risk-kernel.axis.svc.cluster.local:50051"

async def main() -> int:
    trace_id = secrets.token_hex(16)          # kernel requires exactly /^[0-9a-f]{32}$/
    client = GrpcGateClient(KERNEL_TARGET, token=TOKEN, timeout=10.0)
    req = EvaluateRequest(
        tenant_id=TENANT, trace_id=trace_id, span_id=secrets.token_hex(16),
        actor_type=ActorType.AGENT, actor_id="smoke-agent", pid=new_pid(),
        blueprint_name="claims-triage", blueprint_version="1.0.0",
        enforcement_point=EnforcementPoint.TOOL_CALL, action="lookup-claim",
        context={
            "tool": {"name": "lookup-claim", "side_effects": "read"}, "args": {},
            "data": {"phi": False}, "tenant": {"id": TENANT},
            "agent": {"name": "claims-triage", "version": "1.0.0"},
            "run": {"id": "smoke-run-1"}, "actor": {"type": "agent", "id": "smoke-agent"},
            "enforcement_point": "tool_call",
        },
    )
    decision = await client.evaluate(req)
    print(f"TRACE_ID={trace_id} DECISION={decision.decision} REASON={decision.reason}")
    return 0 if str(decision.decision) in ("Decision.ALLOW", "ALLOW") else 1

sys.exit(asyncio.run(main()))
```

Run it inside an already-Ready pod in the `axis` namespace (see NEEDS #513 for why a *brand-new*
pod's first attempt can spuriously `ECONNREFUSED`):

```bash
kubectl cp smoke_gate.py axis/<runtime-pod>:/tmp/smoke_gate.py
kubectl exec -n axis <runtime-pod> -- python /tmp/smoke_gate.py
# TRACE_ID=a25ce83a0310e6530666e6e688cda4ef DECISION=Decision.ALLOW REASON=baseline-deny/allow-read-tools
```

Then verify the real audit row, straight from Postgres (also via a one-off `psql` Job, same
image/approach as steps 5/7):

```sql
SELECT id, tenant_id, decision, enforcement_point, action, trace_id, ts, policy_version, hash, prev_hash
FROM audit_events WHERE trace_id = 'a25ce83a0310e6530666e6e688cda4ef';
--                   id                  |              tenant_id               | decision | enforcement_point |    action    |             trace_id             |            ts             |             policy_version              |                               hash                               |                            prev_hash
-- fc3483b9-c652-4c7f-8fac-cb7cf920694c | c1057100-0000-4000-8000-000000000001 | ALLOW    | tool_call         | lookup-claim | a25ce83a0310e6530666e6e688cda4ef | 2026-10-17 01:52:45.16+00 | baseline-deny@1.0.0,phi-redaction@1.1.0 | 2a27bda9...96a5d70e | 0000...0000
```

A second run with `action: "update-crm"` / `side_effects: "write"` (not in `baseline-deny`'s
allowlist) produced `DECISION=Decision.DENY REASON=no matching rule (default deny)` — the
fail-closed default, also for real, over the same real gRPC path.

### 9. Tear down

```bash
export PATH="$PATH:$HOME/go/bin"
k3d cluster delete axis-local
docker rmi axis/risk-kernel:dev axis/control-plane:dev axis/runtime:dev axis/db-migrate:dev \
  k3d-tools-local:v5.8.3 bitnami/postgresql:latest  # whatever this pass built/pulled, as needed
docker system prune -f
```

## Known gaps (see `docs/NEEDS.md` for the numbered entries)

- #510 (umbrella: only a 3-service subset was installed and proven; `control-plane` still crashes)
- #512 (kubelet disk-pressure false positive in nested sandboxes)
- #513 (kube-router NetworkPolicy ipset lag for brand-new pods)
- #514 (`control-plane` image missing `policies/control-plane/`)
- #515 (RESOLVED: risk-kernel image missing `proto/` — fixed this session)
- #516 (RESOLVED for 3 of 14 images: non-numeric `USER` breaks `runAsNonRoot`)
- #517 (RESOLVED: risk-kernel chart's `AXIS_RK_TOKENS` wiring needed a file mount, not an env var)
- #518 (Secret/ConfigMap changes don't trigger a pod rollout in any of the 3 charts checked)
- #519 (bitnami postgresql's pinned tag is no longer pullable; `latest` used instead)
- #520 (k3d's own helper images are on the blocked `ghcr.io`; built `k3d-tools` locally instead)
