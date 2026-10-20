# syntax=docker/dockerfile:1.7
# @axis/data-governance — Node 22, multi-stage, non-root. Built from the monorepo root as build context:
#   docker build -f services/data-governance/Dockerfile -t axis/data-governance:dev .
# Runs the DEV/E2E entry point this package actually ships (package.json "dev-server": "node dist/main.js"),
# documented per-service in its own main.ts/dev-server.ts (see docs/NEEDS.md for the production-hardening gaps:
# static bearer tokens, no TLS, in-memory or loopback-only pieces where noted in CLAUDE.md's component table).

# NODE_ENV MUST NOT be set to "production": main.ts exit(2)s if it is. The Helm chart
# leaves NODE_ENV unset.
FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/data-governance
RUN pnpm --filter @axis/data-governance deploy --prod --legacy /out

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
ENV AXIS_GOV_PORT=8080
EXPOSE 8080
# No init system installed (keeps the final stage apk/network-free): Node reaps its own
# children here (no subprocesses are spawned), and Kubernetes sends TERM directly to PID 1.
CMD ["node", "dist/main.js"]
