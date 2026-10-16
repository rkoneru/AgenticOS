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

FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/api-gateway
RUN pnpm --filter @axis/api-gateway deploy --prod --legacy /out

FROM node:22-alpine AS runtime
RUN apk add --no-cache dumb-init curl && addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
# NODE_ENV is deliberately left unset (not "production"): see the gateway's own refusal above.
ENV GW_PORT=8080 \
    GW_HOST=127.0.0.1
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
