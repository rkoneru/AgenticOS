# syntax=docker/dockerfile:1.7
# @axis/eval-hub — Node 22, multi-stage, non-root. Built from the monorepo root as build context:
#   docker build -f services/eval-hub/Dockerfile -t axis/eval-hub:dev .
# Runs the DEV/E2E entry point this package actually ships (package.json "dev-server": "node dist/main.js"),
# documented per-service in its own main.ts/dev-server.ts (see docs/NEEDS.md for the production-hardening gaps:
# static bearer tokens, no TLS, in-memory or loopback-only pieces where noted in CLAUDE.md's component table).

FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/eval-hub
RUN pnpm --filter @axis/eval-hub deploy --prod --legacy /out

FROM node:22-alpine AS runtime
RUN apk add --no-cache dumb-init && addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
ENV NODE_ENV=production \
    AXIS_EVALHUB_PORT=8080
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
