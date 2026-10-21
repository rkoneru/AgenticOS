# syntax=docker/dockerfile:1.7
# @axis/api-gateway (standalone) — apps/api-gateway/src/main.ts, run via its own package.json
# "dev-server" equivalent ("node dist/main.js"). NOTE (docs/NEEDS.md #218, carried into #422+): this
# process's configFromEnv() refuses NODE_ENV=production and GW_HOST must be a loopback address
# ("127.0.0.1" | "::1" | "localhost") — there is no production wiring yet. The container therefore
# listens on 127.0.0.1 only; liveness/readiness probes must run INSIDE the container (exec, not
# httpGet) and the k8s Service cannot actually forward cluster traffic to it until a production
# gateway binds a non-loopback address. See infra/helm/charts/api-gateway/README.md.
# Build from the monorepo root as build context:
#   docker build -f apps/api-gateway/Dockerfile -t axis/api-gateway:dev .

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
RUN pnpm turbo run build --filter=@axis/api-gateway
RUN pnpm --filter @axis/api-gateway deploy --prod --legacy /out

FROM node:22-alpine AS runtime
# Numeric UID/GID (not just a named user): Kubernetes' runAsNonRoot pod securityContext can
# only verify non-root when either the image's USER is numeric or the pod spec pins runAsUser
# itself (same CreateContainerConfigError class found deploying risk-kernel/control-plane/
# runtime to a real k3d cluster, docs/runbooks/local-cluster.md; NEEDS #516).
RUN addgroup -g 10001 -S axis && adduser -u 10001 -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
# A tiny dependency-free probe script: GW_HOST is loopback-only (see above), so kubelet's
# httpGet cannot reach this pod's IP — the chart instead execs this script inside the container.
COPY --chown=axis:axis <<'EOF' /app/healthcheck.js
const http = require("node:http");
const port = process.env.GW_PORT || "8080";
http
  .get({ host: "127.0.0.1", port, path: "/healthz", timeout: 2000 }, (res) => {
    process.exit(res.statusCode === 200 ? 0 : 1);
  })
  .on("error", () => process.exit(1));
EOF
USER axis
# NODE_ENV is deliberately left unset (not "production"): see the gateway's own refusal above.
ENV GW_PORT=8080 \
    GW_HOST=127.0.0.1
EXPOSE 8080
CMD ["node", "dist/main.js"]
