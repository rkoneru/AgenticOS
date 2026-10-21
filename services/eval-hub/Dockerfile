# syntax=docker/dockerfile:1.7
# @axis/eval-hub — Node 22, multi-stage, non-root. Built from the monorepo root as build context:
#   docker build -f services/eval-hub/Dockerfile -t axis/eval-hub:dev .
# Runs the DEV/E2E entry point this package actually ships (package.json "dev-server": "node dist/main.js"),
# documented per-service in its own main.ts/dev-server.ts (see docs/NEEDS.md for the production-hardening gaps:
# static bearer tokens, no TLS, in-memory or loopback-only pieces where noted in CLAUDE.md's component table).

# NODE_ENV MUST NOT be set to "production": this dev-server refuses to start if it is
# (see its own source for the guard). The Helm chart leaves NODE_ENV unset.
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
RUN pnpm turbo run build --filter=@axis/eval-hub
RUN pnpm --filter @axis/eval-hub deploy --prod --legacy /out

FROM node:22-alpine AS runtime
# busybox adduser/addgroup only: no apk/network dependency in the final stage
# Numeric UID/GID (not just a named user): Kubernetes' runAsNonRoot pod securityContext can
# only verify non-root when either the image's USER is numeric or the pod spec pins runAsUser
# itself (same CreateContainerConfigError class found deploying risk-kernel/control-plane/
# runtime to a real k3d cluster, docs/runbooks/local-cluster.md; NEEDS #516).
RUN addgroup -g 10001 -S axis && adduser -u 10001 -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
ENV AXIS_EVALHUB_PORT=8080
EXPOSE 8080
# No init system installed (keeps the final stage apk/network-free): Node reaps its own
# children here (no subprocesses are spawned), and Kubernetes sends TERM directly to PID 1.
CMD ["node", "dist/main.js"]
