# syntax=docker/dockerfile:1.7
# @axis/docs-site — static site (docs/ + OpenAPI reference + ADR index), built by `tsx src/build.ts`
# (make docs-build) into apps/docs-site/dist, then served by nginx. Build from the monorepo root:
#   docker build -f apps/docs-site/Dockerfile -t axis/docs-site:dev .

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
RUN pnpm --filter @axis/docs-site build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
COPY --from=builder /repo/apps/docs-site/dist /usr/share/nginx/html
COPY apps/docs-site/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
