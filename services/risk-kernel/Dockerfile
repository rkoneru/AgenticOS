# syntax=docker/dockerfile:1.7
# @axis/risk-kernel — the fail-closed Risk Kernel. gRPC server (not HTTP); also optionally hosts the
# approvals DEV loopback bridge in-process when AXIS_APPROVALS_DEV_BRIDGE=1 (services/approvals has no
# standalone entrypoint of its own — see docs/adr/0116-helm-chart-layout.md).
# Build from the monorepo root as build context:
#   docker build -f services/risk-kernel/Dockerfile -t axis/risk-kernel:dev .

FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/risk-kernel
RUN pnpm --filter @axis/risk-kernel deploy --prod --legacy /out

FROM node:22-alpine AS runtime
RUN apk add --no-cache dumb-init && addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /out ./
USER axis
ENV NODE_ENV=production \
    AXIS_RK_PORT=50051 \
    AXIS_BIND_HOST=0.0.0.0
EXPOSE 50051
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
