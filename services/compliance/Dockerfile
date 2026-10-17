# syntax=docker/dockerfile:1.7
# @axis/compliance — Node 22, multi-stage, non-root. Built from the monorepo root as build context:
#   docker build -f services/compliance/Dockerfile -t axis/compliance:dev .
# Runs the DEV/E2E entry point this package actually ships (package.json "dev-server": "node dist/main.js"),
# documented per-service in its own main.ts/dev-server.ts (see docs/NEEDS.md for the production-hardening gaps:
# static bearer tokens, no TLS, in-memory or loopback-only pieces where noted in CLAUDE.md's component table).

# NODE_ENV MUST NOT be set to "production": this dev-server refuses to start if it is
# (see its own source for the guard). The Helm chart leaves NODE_ENV unset.
FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/compliance
RUN pnpm --filter @axis/compliance deploy --prod --legacy /out

FROM node:22-alpine AS runtime
# busybox adduser/addgroup only: no apk/network dependency in the final stage
RUN addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
ENV AXIS_COMPLIANCE_PORT=8080
EXPOSE 8080
# No init system installed (keeps the final stage apk/network-free): Node reaps its own
# children here (no subprocesses are spawned), and Kubernetes sends TERM directly to PID 1.
CMD ["node", "dist/main.js"]
