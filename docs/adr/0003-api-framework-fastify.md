# 0003. Control-plane API framework: Fastify

Status: Accepted · Date: 2026-09-30

## Context

The control plane (Node 22, TypeScript) serves `/v1` REST generated from an OpenAPI 3.1 source of truth and a gRPC surface.

## Options

1. **Fastify** — schema-first (JSON Schema validation/serialization built in), low overhead, plugin model, good OTel support.
2. **NestJS** — batteries included (DI, modules) but heavier, decorator-driven, and its OpenAPI is code-first, which inverts our "spec is the source of truth" rule. Its default adapter is Express or Fastify anyway.

## Decision

Fastify, with routes validated against schemas derived from `openapi/axis-v1.yaml`. No tRPC: there is no internal TS↔TS boundary that gRPC/OpenAPI does not already cover.

## Consequences

We write our own module boundaries (plain functions and plugins) rather than relying on DI. The p99 < 200 ms at 1k RPS target is easier to meet. Contract tests compare live routes to the OpenAPI document.
