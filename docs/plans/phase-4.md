# Phase 4 plan — Memory, tools, and execution surfaces

Goal: agents use memory, MCP, code and browser tools; every call appears in audit with a policy decision.

| #   | Component             | Location                                              | Coverage | Notes |
| --- | --------------------- | ----------------------------------------------------- | -------- | ----- |
| A   | Memory service        | `services/memory` (TS) + Python runtime `MemoryBackend` | 85% (tenancy-critical ACL paths 95%) | run/session/long-term/vector memory on Postgres+pgvector (migration 0003 tables; additive migration only with ADR if needed), KB ingestion, chunking, embeddings via an injected embedder (fake in tests), ACL-aware retrieval, tenant RLS, PHI never persisted unredacted |
| B   | MCP client + server   | `runtime/src/axis_runtime/mcp/` (client), `services/mcp-server` or runtime module (server) | 85% | agents consume external MCP servers (stdio/HTTP) — every call is an Action through the gate; server exposes AXIS agents/tools — every inbound call is authenticated, tenant-scoped, gated; SSRF-safe endpoints; tool-description prompt-injection handling |
| C   | Code sandbox          | `runtime/src/axis_runtime/sandbox/`                   | 85% | isolated, no-network default, rlimits (cpu/mem/files/procs), wall timeout, artifact capture, output caps; backend interface with a Linux namespace/rlimit implementation (no Docker daemon here) — honest label, not a security boundary claim without evidence; gVisor/Firecracker backend recorded in NEEDS |
| D   | Browser workers       | `runtime/src/axis_runtime/browser/`                   | 85% | Playwright (preinstalled chromium), isolated context per run, domain allowlist enforced at network layer incl. redirects/subresources, SSRF/private-range block, capture (URL, title, text, screenshot hash) into audit via the gate |
| E   | Integration e2e       | `e2e/test_phase4_tools.py`, `make e2e-phase4`         | -        | agent uses memory + MCP + code + browser; every call has a gate decision in the audit chain |

Rules: every action still passes the Risk Kernel (bypass test stays green; new modules scanned); fail-closed; tenant isolation; NEEDS rows continue after the highest.
