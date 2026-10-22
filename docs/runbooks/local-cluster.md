# Running AXIS on a real local Kubernetes cluster (k3d)

Phase 10, workstream `phase10-cluster`. This is the honest record of what was actually run
against a real k3d cluster in this sandboxed dev environment, not a design document: every
command here was executed for real; every gap below was found live, not guessed. See
`docs/plans/phase-10.md` for the phase's overall scope and `infra/helm/README.md` /
`docs/adr/0116-helm-chart-layout.md` for the chart layout this builds on.

This run was done across two sessions: a first pass (2026-10-17) that got as far as building the
real images and hit real build/scheduling blockers, and a second pass (2026-10-20, after a
container cycle wiped all Docker images and the first pass's cluster) that re-built everything
from scratch using this file's own instructions, found two more real gaps the first pass's draft
had missed (the Go-module CA trust for the `k3d-tools` build, and pinning the Postgres password so
the hardcoded connection strings below actually match), and completed the full path through
teardown. Every command and every piece of real output below — trace IDs, decisions, audit rows,
hash values — is from the 2026-10-20 run unless stated otherwise.

## What was achieved

- A real k3d (k3s-in-Docker) single-node cluster, created and torn down for real.
- Real container images built from this repo's own Dockerfiles for `risk-kernel`,
  `control-plane` and the Python `runtime` (run-server), imported into the cluster (no external
  registry).
- `helm install`/`helm upgrade` of a **subset** of the `infra/helm/axis` umbrella chart (Postgres
  - risk-kernel + control-plane + runtime; the other 11 AXIS service charts disabled — see
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

## What was _not_ achieved (be precise about this)

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

````bash
git clone --depth 1 --branch v5.8.3 https://github.com/k3d-io/k3d.git /tmp/k3dsrc
```bash
cat > /tmp/k3dsrc/tools/Dockerfile.local <<'EOF'
FROM golang:1.22.4-alpine3.20 AS builder
WORKDIR /app
COPY ca-bundle.cr[t] /tmp/
RUN if [ -f /tmp/ca-bundle.crt ]; then cp /tmp/ca-bundle.crt /usr/local/share/ca-certificates/ci-proxy.crt && update-ca-certificates; fi
COPY . .
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod GOPROXY=https://proxy.golang.org,direct
RUN go build -o bin/k3d-tools .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/bin/k3d-tools .
ENTRYPOINT [ "/app/k3d-tools"]
EOF
cp /root/.ccr/ca-bundle.crt /tmp/k3dsrc/tools/ca-bundle.crt
cd /tmp/k3dsrc/tools
docker build --network=host -f Dockerfile.local -t k3d-tools-local:v5.8.3 .
````

This CA step is **required**, not optional: an earlier draft of this runbook tried `ENV
NODE_EXTRA_CA_CERTS`-style trust only inside the three AXIS Dockerfiles (step 3) and omitted it
here, on the theory that `--network=host` alone would be enough for a bare `go build`. Re-running
this for real in this session hit exactly the TLS failure that theory predicted:
`proxy.golang.org`'s cert is signed by this sandbox's intercepting proxy CA, and a Go toolchain
with no CA trust rejects it outright (`tls: failed to verify certificate: x509: certificate signed
by unknown authority`) — confirmed by the actual build log, then fixed by installing the CA into
the Alpine build stage's system trust store before `go build` runs.

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

Writing a _more negative_ `oom_score_adj` than a process's enclosing container already has is
blocked in this nested sandbox (the same restriction that produces k3s's own non-fatal
`"Failed to ensure state" ... failed to apply oom score -999 ... permission denied` warning in its
logs). containerd's CRI plugin has a config flag for exactly this situation —
`restrict_oom_score_adj = true` — which clamps the OOM score adjustment it asks for to what the
_containerd process's own_ current value allows, instead of the CRI-computed value unconditionally.
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

**Also pin the Postgres auth passwords in that same values file**
(`postgresql.auth.postgresPassword` / `postgresql.auth.password`), not just the image tag. Found
live in this session: without a pin, the bitnami chart generates a fresh random password on every
`helm install`, but this values file _also_ hardcodes matching `postgresql://...` connection
strings into the risk-kernel and control-plane secrets further down — on the first install those
strings' passwords and the chart's actual generated secret (`kubectl get secret axis-postgresql`)
simply didn't match, and both services failed to connect until the values were pinned and the
release reinstalled. Dev-only fixed passwords, never used outside this throwaway cluster.

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

There is **no `kubectl` binary** available directly in this sandbox (and no outbound path to fetch
one — `dl.k8s.io`/`storage.googleapis.com` are not on the allowlist). Two ways to get one, both
used in this session:

- Via the node container, for anything that doesn't need a local process to reach the API server
  over a forwarded port:
  ```bash
  docker exec -i k3d-axis-local-server-0 kubectl "$@"
  ```
- A **real host-side `kubectl`**, by copying k3s's own embedded binary out of the node (k3s ships
  `kubectl` as a symlink to the `k3s` binary itself, which implements the same CLI when invoked as
  `kubectl`):
  ```bash
  docker cp k3d-axis-local-server-0:$(docker exec k3d-axis-local-server-0 readlink -f /bin/kubectl) /tmp/k3s
  chmod +x /tmp/k3s
  mkdir -p /tmp/kbin && ln -sf /tmp/k3s /tmp/kbin/kubectl
  export PATH="/tmp/kbin:$PATH"
  export KUBECONFIG=/tmp/kubeconfig-axis.yaml
  kubectl get pods -n axis   # works like any normal kubectl, including port-forward
  ```
  This second form is needed for `kubectl port-forward`, which must run as a process on the same
  host as the thing connecting to the forwarded port (step 7 below).

### 7. Apply the DB migration and seed a tenant, from the host via `kubectl port-forward`

The prior draft of this runbook planned a one-off migration Job image for this step (same pattern
as steps 3/5). Re-running this for real, the much simpler path worked directly: port-forward
Postgres to the host and run this repo's own migration CLI and `psql` against `127.0.0.1` — no
extra image needed.

```bash
kubectl -n axis port-forward svc/axis-postgresql 15432:5432 &   # background; kill when done

PG_ADMIN_URL="postgresql://postgres:<postgresPassword from values-local-cluster-subset.yaml>@127.0.0.1:15432/axis"

DATABASE_URL="$PG_ADMIN_URL" pnpm --filter @axis/db exec tsx src/cli.ts
# applied: 0001_tenancy_and_rls, 0002_core_tables, ... 0017_governance_settings_read

psql "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 -tAc \
  "INSERT INTO tenants (id, slug, name, region) VALUES ('c1057100-0000-4000-8000-000000000001', 'cluster-e2e', 'cluster-e2e', 'us') ON CONFLICT DO NOTHING"
```

`DATABASE_URL` must be the **superuser** (`postgres`) role, matching
`e2e/test_phase2_core_loop.py`'s own `PG_ADMIN_URL` pattern — `CREATE EXTENSION` in the early
migrations needs superuser, and the `axis_app`/`axis` roles the migrations create are not
automatically grantable to each other.

### 8. Drive the real gRPC path and verify the real audit row

A one-off Python script, run **inside the cluster** via `kubectl cp` + `kubectl exec`, using the
real `axis_runtime.gate.GrpcGateClient` already present in the `axis/runtime:dev` image, against
the real risk-kernel pod's ClusterIP. It exercises both the ALLOW and the default-DENY path in one
run, so the two decisions' hash-chain linkage can be checked directly:

```python
import asyncio, secrets, sys
from axis_runtime.gate import ActorType, EnforcementPoint, EvaluateRequest, GrpcGateClient
from axis_runtime.process import new_pid

TENANT = "c1057100-0000-4000-8000-000000000001"
TOKEN = "cluster-e2e-44a38b113b56862a"
KERNEL_TARGET = "axis-risk-kernel.axis.svc.cluster.local:50051"


async def run_one(action: str, side_effects: str) -> tuple[str, str]:
    trace_id = secrets.token_hex(16)  # kernel requires exactly /^[0-9a-f]{32}$/
    client = GrpcGateClient(KERNEL_TARGET, token=TOKEN, timeout=10.0)
    req = EvaluateRequest(
        tenant_id=TENANT,
        trace_id=trace_id,
        span_id=secrets.token_hex(16),
        actor_type=ActorType.AGENT,
        actor_id="smoke-agent",
        pid=new_pid(),
        blueprint_name="claims-triage",
        blueprint_version="1.0.0",
        enforcement_point=EnforcementPoint.TOOL_CALL,
        action=action,
        context={
            "tool": {"name": action, "side_effects": side_effects},
            "args": {},
            "data": {"phi": False},
            "tenant": {"id": TENANT},
            "agent": {"name": "claims-triage", "version": "1.0.0"},
            "run": {"id": "smoke-run-1"},
            "actor": {"type": "agent", "id": "smoke-agent"},
            "enforcement_point": "tool_call",
        },
    )
    decision = await client.evaluate(req)
    print(
        f"TRACE_ID={trace_id} ACTION={action} DECISION={decision.decision} REASON={decision.reason}"
    )
    return trace_id, str(decision.decision)


async def main() -> int:
    t1, d1 = await run_one("lookup-claim", "read")
    t2, d2 = await run_one("update-crm", "write")
    return 0 if ("ALLOW" in d1 and "DENY" in d2) else 1


sys.exit(asyncio.run(main()))
```

```bash
kubectl cp smoke_gate.py axis/<runtime-pod>:/tmp/smoke_gate.py
kubectl exec -n axis <runtime-pod> -- /app/.venv/bin/python /tmp/smoke_gate.py
```

Real output from this session:

```
TRACE_ID=3a2a6347469a99459e9c4c5637ab4bbd ACTION=lookup-claim DECISION=ALLOW REASON=baseline-deny/allow-read-tools
TRACE_ID=0da02d33f506099acf1e29d8b0bd9e2b ACTION=update-crm DECISION=DENY REASON=no matching rule (default deny)
```

Then verify the real audit rows, straight from Postgres (same `kubectl port-forward` + `psql` as
step 7):

```sql
SELECT id, tenant_id, decision, enforcement_point, action, trace_id, ts, policy_version, hash, prev_hash
FROM audit_events WHERE trace_id IN ('3a2a6347469a99459e9c4c5637ab4bbd','0da02d33f506099acf1e29d8b0bd9e2b');
```

Real rows from this session (the hash chain is live here, not illustrative: the DENY row's
`prev_hash` is exactly the ALLOW row's `hash`):

```
40465c29-cc78-4d8e-a7f7-5e5be17396da | c1057100-0000-4000-8000-000000000001 | ALLOW | tool_call | lookup-claim | 3a2a6347469a99459e9c4c5637ab4bbd | 2026-10-20 18:15:06.408+00 | baseline-deny@1.0.0,phi-redaction@1.1.0 | 4dd61dffd81e5991b60d46ac39b44834ae829871ab812ad9b36eb5821c039810 | 0000...0000
9d147733-a1cd-4061-9fed-4d1073300189 | c1057100-0000-4000-8000-000000000001 | DENY  | tool_call | update-crm   | 0da02d33f506099acf1e29d8b0bd9e2b | 2026-10-20 18:15:06.46+00  | baseline-deny@1.0.0,phi-redaction@1.1.0 | a200265fe4d760214147c07c65db1c6737de6d4d80d57943f138d1ade0a5b89e | 4dd61dffd81e5991b60d46ac39b44834ae829871ab812ad9b36eb5821c039810
```

This is the full Phase-2 core-loop decision path (ABL/runtime process model → real gRPC →
real fail-closed Risk Kernel pod → real hash-chained Postgres audit row), run for real against a
real k3d cluster, not the ephemeral-process harness `make e2e-core` normally uses, and not
reconstructed after the fact — the trace IDs, decisions and hash values above are copied verbatim
from this session's actual command output.

### 9. Tear down

```bash
pkill -f "port-forward svc/axis-postgresql"
export PATH="$PATH:$HOME/go/bin"
k3d cluster delete axis-local
docker rmi axis/risk-kernel:dev axis/control-plane:dev axis/runtime:dev \
  k3d-tools-local:v5.8.3 bitnami/postgresql:latest rancher/k3s:v1.32.5-k3s1 \
  rancher/local-path-provisioner:v0.0.31 rancher/mirrored-coredns-coredns:1.12.1 \
  rancher/mirrored-library-busybox:1.36.1 rancher/mirrored-metrics-server:v0.7.2 \
  rancher/mirrored-pause:3.6
docker system prune -af
docker builder prune -af
```

Confirmed clean in this session: `k3d cluster delete` removed the node container (`docker ps -a`
empty afterward), all images above were removed, and `df -h /` returned to the same 49-50% used
baseline the session started at.

## Known gaps (see `docs/NEEDS.md` for the numbered entries)

- #510 (RESOLVED further: 8 of 14 AXIS service charts now proven Ready on a real cluster)
- #512 (kubelet disk-pressure false positive in nested sandboxes)
- #513 (kube-router NetworkPolicy ipset lag for brand-new pods)
- #514 (RESOLVED, confirmed on a live cluster this pass: `control-plane` reaches `1/1 Running`)
- #515 (RESOLVED: risk-kernel image missing `proto/` — fixed this session)
- #516 (RESOLVED for 3 of 14 images: non-numeric `USER` breaks `runAsNonRoot`)
- #517 (RESOLVED: risk-kernel chart's `AXIS_RK_TOKENS` wiring needed a file mount, not an env var)
- #518 (Secret/ConfigMap changes don't trigger a pod rollout in any of the 3 charts checked)
- #519 (bitnami postgresql's pinned tag is no longer pullable; `latest` used instead)
- #520 (k3d's own helper images are on the blocked `ghcr.io`; built `k3d-tools` locally instead)
- #521 (RESOLVED: `k3d-tools` build also needs the sandbox's proxy CA trusted)
- #522 (RESOLVED: hardcoded Postgres connection strings needed a matching pinned password)
- #523 (RESOLVED: 9 services default to a loopback-only listener; a k8s `httpGet` probe can't reach it)
- #524 (RESOLVED: `CP_RUNTIME_TOKENS` needed to be a JSON object, not a bare string)
- #525 (RESOLVED: Kubernetes' injected `<SVC>_PORT` env var collided with services' own same-named port var)
- #526 (open: nothing provisions `axis_app` role membership for `control-plane`'s own login role)

## Session 3 (this pass): control-plane confirmed Ready + 4 more services deployed

This pass re-ran the whole runbook above from scratch (fresh container, no prior images or
cluster) specifically to answer two questions the prior pass's `docker run`-only verification
could not: does `control-plane`'s #514 fix actually reach `Ready` on a **live** cluster, and does
risk-kernel's `grpc` native readiness probe (ADR 0118) actually work against this cluster's real
kubelet? Both: yes.

### What's new in this pass

1. **`control-plane` confirmed `1/1 Running` on a live k3d cluster** (not just `docker run`).
   Getting there surfaced two more real bugs beyond #514's own fix, both found live and fixed:
   - `CP_RUNTIME_TOKENS` in `values-local-cluster-subset.yaml` was a bare string, but
     `control-plane`'s `main.ts` does `JSON.parse()` on it and crashes otherwise (#524).
   - The `axis` Postgres login role the bitnami chart provisions was never a member of the
     `axis_app` group role the migrations grant table/schema privileges to, so every real DB
     write 500'd with `permission denied for schema axis` until a one-off
     `GRANT axis_app TO axis;` was run by hand (#526, still open — `control-plane`'s dev entry
     point has no `CP_PG_ROLE`/`SET ROLE` option the way `risk-kernel`'s does).
   ```bash
   PGPASSWORD=<postgresPassword> psql -h 127.0.0.1 -p 15432 -U postgres -d axis -c \
     "GRANT axis_app TO axis;"
   ```
   After both fixes, a real `POST /platform/v1/tenants` call through the real control-plane
   (Bearer platform token) returned a real `201` with a tenant row confirmed in Postgres by id.

2. **Risk Kernel's `grpc` readiness/liveness probe (ADR 0118) confirmed working for real**:
   `kubectl -n axis describe pod axis-risk-kernel-...` shows
   `Readiness: grpc <pod>:50051 delay=3s timeout=1s period=5s #success=1 #failure=3` (the native
   gRPC probe type, not `tcpSocket`), and the pod reaches `1/1 Running` using it. This cluster's
   Kubernetes version is `v1.32.5+k3s1` — well past 1.24, where the `grpc` probe type went GA, so
   it works without any feature-gate flag.

3. **Four more AXIS service charts deployed for the first time ever on a live cluster**:
   `registry`, `billing`, `data-governance` and `docs-site`. Images built the same way as the
   core three (`docker build --network=host --build-context ciproxyca=... --build-arg
   CI_PROXY_CA_BASE=ciproxyca`), imported the same way (`docker save` + `ctr -n k8s.io images
   import` inside the node — `k3d image import` is still broken here, #520), and enabled in
   `values-local-cluster-subset.yaml` with real Postgres URLs, bearer tokens and seal/master keys
   (dev-only fixed values, same pattern as the existing risk-kernel/control-plane wiring). All
   four reached `1/1 Running`. `docs-site` and `data-governance` needed no further fix beyond
   what was already in the chart; `registry` and `billing` additionally needed the
   `enableServiceLinks: false` fix below.

4. **A new, previously-undiscovered bug found deploying `registry` and `billing`**: Kubernetes
   injects Docker-links-style `<SVC>_PORT=tcp://<ip>:<port>` env vars into every pod for every
   Service already in the namespace (uppercased, `-` → `_`), unless the pod spec sets
   `enableServiceLinks: false`. `registry` (Service `axis-registry`) and `billing` (Service
   `axis-billing`) each read their own HTTP port from `AXIS_REGISTRY_PORT`/`AXIS_BILLING_PORT`
   env vars — which collide exactly with the injected name — so the injected `"tcp://..."` string
   silently clobbered the real port value and crashed `http.Server.listen()` with
   `ERR_SOCKET_BAD_PORT` (`Number("tcp://...")` is `NaN`). `data-governance`
   (`AXIS_GOV_PORT`, no collision) and `docs-site` (nginx, no such env var) happened not to hit
   this in the same batch — not evidence the bug doesn't apply elsewhere. Fixed by adding
   `enableServiceLinks: false` to all 15 AXIS deployment templates (every chart, not just the two
   that collided today; NEEDS #525).

5. **Node-level image garbage collection evicted already-imported bootstrap images mid-session**:
   partway through this pass, `rancher/mirrored-pause:3.6` (and `mirrored-library-busybox`)
   disappeared from `crictl images` even though they had been successfully imported and used by
   earlier pods, causing new pod sandboxes to fail with `FailedCreatePodSandBox` /
   `ErrImagePull` trying to re-pull them from the (unreachable in this sandbox at the time)
   registry. The `pinned_images.sandbox` setting in `config.toml.tmpl` did not prevent this. Fixed
   by just re-`docker save`+`ctr images import`-ing the missing images again (seconds, since
   they're tiny) — not deeply root-caused, logged here for the next person who hits the same
   `FailedCreatePodSandBox` after a run that has been up a while.

6. **A real second end-to-end check, through control-plane, alongside the original gRPC smoke
   test**: a real HTTP `POST /platform/v1/tenants` call from inside the `runtime` pod to the real
   `control-plane` Service, authenticated with the real platform bearer token, provisioning a real
   tenant through `Provisioner.signup()` (policy pack compile via the real `opa` binary + a real
   transactional Postgres write), confirmed by querying the resulting `tenant_id` directly in
   Postgres:
   ```
   HTTP 201 {"tenant_id":"5b065d16-1566-4255-b5df-61ad306354f2", ...}
   # psql: id | slug | name | region
   #      5b065d16-... | cluster-e2e-2 | Cluster E2E Co | us-east-1
   ```

### Not attempted in this pass

`marketplace`, `memory`, `channels`, `eval-hub`, `compliance`, `api-gateway` and `console` were
not built or deployed in this pass. This was a time/disk budget decision (each additional
Node/Next.js image costs tens to hundreds of MB, and this sandbox's disk is a hard, shared,
~20-23 GB-free allowance that a full 14-service deploy plus Postgres plus the node's own
containerd overlay would not comfortably fit without very careful pruning between every single
image) — not a technical blocker found and abandoned. `api-gateway`'s chart deliberately has no
working Service path yet (NEEDS #506: its own loopback-only posture needs an exec-probe pattern,
already wired, but it still can't carry real Service traffic) and would not have been a
meaningful target even with more budget.

Final pod state at the end of this pass (before teardown):

```
NAME                                       READY   STATUS    RESTARTS   AGE
axis-billing-...                           1/1     Running   0          ...
axis-control-plane-...                     1/1     Running   0          ...
axis-data-governance-...                   1/1     Running   0          ...
axis-docs-site-...                         1/1     Running   0          ...
axis-postgresql-0                          1/1     Running   0          ...
axis-registry-...                          1/1     Running   0          ...
axis-risk-kernel-...                       1/1     Running   0          ...
axis-runtime-run-server-...                1/1     Running   0          ...
```

Cluster torn down cleanly afterward the same way as prior sessions (`k3d cluster delete` +
`docker rmi` + `docker system/builder prune -af`) — see the teardown section above.
