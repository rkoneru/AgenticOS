# syntax=docker/dockerfile:1.7
# @axis/risk-kernel — the fail-closed Risk Kernel. gRPC server (not HTTP); also optionally hosts the
# approvals DEV loopback bridge in-process when AXIS_APPROVALS_DEV_BRIDGE=1 (services/approvals has no
# standalone entrypoint of its own — see docs/adr/0116-helm-chart-layout.md).
# Build from the monorepo root as build context:
#   docker build -f services/risk-kernel/Dockerfile -t axis/risk-kernel:dev .
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
RUN pnpm turbo run build --filter=@axis/risk-kernel
RUN pnpm --filter @axis/risk-kernel deploy --prod --legacy /out

FROM node:22-alpine AS runtime
RUN addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
ENV AXIS_RK_PORT=50051 \
    AXIS_BIND_HOST=0.0.0.0
EXPOSE 50051
CMD ["node", "dist/main.js"]
