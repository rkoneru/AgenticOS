# syntax=docker/dockerfile:1.7
# @axis/console — Next.js "standalone" server output (apps/console/next.config.ts: output: "standalone").
# Build from the monorepo root as build context:
#   docker build -f apps/console/Dockerfile -t axis/console:dev .

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
RUN pnpm turbo run build --filter=@axis/console

FROM node:22-alpine AS runtime
# Numeric UID/GID (not just a named user): Kubernetes' runAsNonRoot pod securityContext can
# only verify non-root when either the image's USER is numeric or the pod spec pins runAsUser
# itself (same CreateContainerConfigError class found deploying risk-kernel/control-plane/
# runtime to a real k3d cluster, docs/runbooks/local-cluster.md; NEEDS #516).
RUN addgroup -g 10001 -S axis && adduser -u 10001 -S axis -G axis
WORKDIR /app
# .next/standalone's own tree is copied AS-IS (monorepo root at /app, server.js under
# apps/console/): its node_modules entries are pnpm symlinks with relative targets like
# "../../../node_modules/.pnpm/...", which only resolve correctly at this original nesting depth.
COPY --from=builder --chown=axis:axis /repo/apps/console/.next/standalone ./
COPY --from=builder --chown=axis:axis /repo/apps/console/.next/static ./apps/console/.next/static
USER axis
ENV NODE_ENV=production \
    PORT=3100 \
    HOSTNAME=0.0.0.0
EXPOSE 3100
CMD ["node", "apps/console/server.js"]
