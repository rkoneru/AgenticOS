# syntax=docker/dockerfile:1.7
# @axis/control-plane — Node 22, multi-stage, non-root. Built from the monorepo root as build context:
#   docker build -f services/control-plane/Dockerfile -t axis/control-plane:dev .
# Runs the DEV/E2E entry point this package actually ships (package.json "dev-server": "node dist/main.js"),
# documented per-service in its own main.ts/dev-server.ts (see docs/NEEDS.md for the production-hardening gaps:
# static bearer tokens, no TLS, in-memory or loopback-only pieces where noted in CLAUDE.md's component table).
#
# Building behind a TLS-intercepting egress proxy (e.g. this repo's sandboxed dev environments):
# pass --build-context ciproxyca=<dir containing ca-bundle.crt> --build-arg CI_PROXY_CA_BASE=ciproxyca
# --network=host. Omit all three and this is a no-op (NODE_EXTRA_CA_CERTS points at a file that is
# never created, which Node silently ignores). See docs/runbooks/local-cluster.md.
ARG CI_PROXY_CA_BASE=ca-empty
FROM scratch AS ca-empty
FROM ${CI_PROXY_CA_BASE} AS ca-src

FROM node:22-alpine AS builder
COPY --from=ca-src ca-bundle.cr[t] /tmp/
RUN if [ -f /tmp/ca-bundle.crt ]; then cp /tmp/ca-bundle.crt /tmp/ci-proxy-ca.pem; fi
ENV NODE_EXTRA_CA_CERTS=/tmp/ci-proxy-ca.pem
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/control-plane
RUN pnpm --filter @axis/control-plane deploy --prod --legacy /out

# Authorizer.fromPackFile() (src/authz.ts) and provisioning.ts's default baseline pack compile
# their policy pack to Rego/Wasm at process startup via packages/policy, which shells out to a
# real `opa` binary (OPA_BIN env var, default "opa" on PATH) — not just a build-time tool here.
# The final stage had no such binary, so after the policies/ COPY fix above the process still
# failed to start, now with "opa binary not found" instead of ENOENT on pack.yaml. Fetch the
# same pinned static OPA build already used by infra/compose/docker-compose.yml and
# docs/runbooks/saas-e2e.md (0.70.0) once, in its own stage, and copy the binary into the
# runtime image (statically linked: no further libc/apk dependency).
FROM node:22-alpine AS opa
COPY --from=ca-src ca-bundle.cr[t] /tmp/
RUN if [ -f /tmp/ca-bundle.crt ]; then cp /tmp/ca-bundle.crt /tmp/ci-proxy-ca.pem; fi
ENV NODE_EXTRA_CA_CERTS=/tmp/ci-proxy-ca.pem
# busybox wget has no --ca-certificate flag; Node's own https (fetch) already honors
# NODE_EXTRA_CA_CERTS the same way the builder stage's pnpm install does above.
RUN node -e "const fs=require('fs');fetch('https://github.com/open-policy-agent/opa/releases/download/v0.70.0/opa_linux_amd64_static').then(r=>{if(!r.ok)throw new Error('http '+r.status);return r.arrayBuffer()}).then(b=>{fs.writeFileSync('/opa',Buffer.from(b));fs.chmodSync('/opa',0o755)}).catch(e=>{console.error(e);process.exit(1)})"

FROM node:22-alpine AS runtime
# busybox adduser/addgroup only: no apk/network dependency in the final stage
# Numeric UID/GID (not just a named user): Kubernetes' runAsNonRoot pod securityContext can only
# verify non-root when either the image's USER is numeric or the pod spec pins runAsUser itself
# (see infra/helm/charts/*/templates/deployment.yaml's podSecurityContext.runAsUser, which this
# repo's charts now set to the same 10001 — found as a real CreateContainerConfigError deploying
# to a live k3d cluster, docs/runbooks/local-cluster.md).
RUN addgroup -g 10001 -S axis && adduser -u 10001 -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
# services/control-plane/src/authz.ts and src/provisioning.ts each resolve a policy pack path
# relative to their own compiled dist file (../../../policies/<pack>/pack.yaml from the monorepo
# layout), which lands on /policies/<pack>/ in this flattened image — `pnpm deploy --prod` only
# packages this workspace, never the sibling monorepo-root policies/ directory, so the process
# crashed with ENOENT on policies/control-plane/pack.yaml until this COPY was added (found as a
# real CrashLoopBackOff deploying to a live k3d cluster, NEEDS #514; same pattern as risk-kernel's
# proto/ fix, NEEDS #515, docs/runbooks/local-cluster.md).
COPY --chown=axis:axis policies/ /policies/
COPY --from=opa /opa /usr/local/bin/opa
USER axis
ENV CP_PORT=8080
EXPOSE 8080
# No init system installed (keeps the final stage apk/network-free): Node reaps its own
# children here (no subprocesses are spawned), and Kubernetes sends TERM directly to PID 1.
CMD ["node", "dist/main.js"]
