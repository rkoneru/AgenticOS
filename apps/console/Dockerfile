# syntax=docker/dockerfile:1.7
# @axis/console — Next.js "standalone" server output (apps/console/next.config.ts: output: "standalone").
# Build from the monorepo root as build context:
#   docker build -f apps/console/Dockerfile -t axis/console:dev .

FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo run build --filter=@axis/console

FROM node:22-alpine AS runtime
RUN addgroup -S axis && adduser -S axis -G axis
WORKDIR /app
# .next/standalone already contains a minimal node_modules and a server.js that serves on PORT.
COPY --from=builder --chown=axis:axis /repo/apps/console/.next/standalone/apps/console ./
COPY --from=builder --chown=axis:axis /repo/apps/console/.next/standalone/node_modules ./node_modules
COPY --from=builder --chown=axis:axis /repo/apps/console/.next/static ./.next/static
COPY --from=builder --chown=axis:axis /repo/apps/console/public ./public
USER axis
ENV NODE_ENV=production \
    PORT=3100 \
    HOSTNAME=0.0.0.0
EXPOSE 3100
CMD ["node", "server.js"]
