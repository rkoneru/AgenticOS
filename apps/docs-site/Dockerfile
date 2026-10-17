# syntax=docker/dockerfile:1.7
# @axis/docs-site — static site (docs/ + OpenAPI reference + ADR index), built by `tsx src/build.ts`
# (make docs-build) into apps/docs-site/dist, then served by nginx. Build from the monorepo root:
#   docker build -f apps/docs-site/Dockerfile -t axis/docs-site:dev .

FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @axis/docs-site build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
COPY --from=builder /repo/apps/docs-site/dist /usr/share/nginx/html
COPY apps/docs-site/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
