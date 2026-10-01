# Runbook: Phase 4 tools e2e (`make e2e-phase4`)

Status: runs locally, **CI job unrun remotely** (NEEDS #3). Spec: `docs/spec/{memory,mcp,sandbox,browser}.md`, ADR 0014.

## Prerequisites

- Node 22 + pnpm, `uv sync --all-packages`, `pnpm build` (the target does it), `opa` on PATH for `make policy-test`.
- Postgres 16 + pgvector: `infra/scripts/with-pg.sh` starts a throwaway cluster, or set `PG_ADMIN_URL` (CI service container).
- **Unprivileged user namespaces** (`unshare --user --map-root-user --net --pid --mount`). Without them the sandbox refuses to run and
  the e2e fails at its preflight by design. On Ubuntu 24.04: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
- A Playwright Chromium matching `playwright>=1.56,<1.57` (`PLAYWRIGHT_BROWSERS_PATH`, or `uv run playwright install chromium`).

## What it starts

Per module: a throwaway database (migrated, two tenants), the Risk Kernel (policy bundle `e2e/policies/phase4-tools`), the memory dev
server (a KB with three differently-ACL'd documents). Per test: the local fixture site (two servers), Chromium, the stdio MCP server
(`runtime/tests/fake_mcp_stdio.py e2e`, from an operator catalog), the sandbox. The LLM is a scripted fake; in the injection tests it
obeys the injected text on purpose.

## Reading a failure

`pytest -q e2e/test_phase4_tools.py -x` prints the per-trace summary (one decision row per gated call) for the main scenario. Kernel and
memory server stderr go to `kernel.err` / `memory.err` in the pytest tmp dir (`/tmp/pytest-of-*/pytest-*/e2e4*`). "audit unavailable"
from the kernel means an audit row violated a DB check (look at `kernel.err`).
