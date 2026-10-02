.PHONY: e2e-phase7 console-e2e docs-build sdk-generate sdk-mutation e2e-core e2e-phase3 e2e-phase4 e2e-phase5 e2e-phase6 contracts-lint freeze install dev dev-down dev-ps dev-health test e2e cov evals lint typecheck policy-test k3s-up tf-plan fmt
COMPOSE := docker compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env.example

install:
	pnpm install --frozen-lockfile
	uv sync --all-packages

dev:
	$(COMPOSE) up -d --wait

dev-down:
	$(COMPOSE) down -v

dev-ps:
	$(COMPOSE) ps

dev-health:
	@bash infra/compose/healthcheck.sh

# OpenAPI 3.1 lint + protobuf lint/build. Needs `pnpm install` first.
contracts-lint:
	pnpm --filter @axis/contracts lint:openapi
	cd proto && pnpm exec buf lint && pnpm exec buf build -o /dev/null

# Regenerate the frozen-contract manifest. Requires an ADR (docs/adr/0007).
freeze:
	pnpm --filter @axis/contracts freeze

lint:
	pnpm lint
	uv run ruff check .
	uv run ruff format --check .

fmt:
	pnpm format
	uv run ruff format .

typecheck:
	pnpm typecheck
	uv run mypy runtime/src sdk/python/src

# DB tests need Postgres 16 + pgvector: uses $PG_ADMIN_URL if set, else starts a throwaway local cluster.
test:
	pnpm test
	uv run pytest runtime sdk/python

# Coverage gates are enforced inside each package (vitest thresholds, pytest --cov-fail-under).
cov:
	pnpm cov
	uv run pytest runtime sdk/python

# Phase 2 exit: real ABL compiler + policy bundle + Risk Kernel (gRPC) + Postgres audit + Python runtime.
# Needs node, pnpm, uv, opa, PostgreSQL 16 (uses $PG_ADMIN_URL or starts a throwaway cluster).
e2e-core:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase2_core_loop.py -p no:cacheprovider --no-cov

# Phase 3 exit: multi-agent run under TKI with enforced budgets, NEXUS stage metrics in the trace, approvals end to end
# (Risk Kernel + approvals service + dev bridge + runtime resolver/re-gate), then the bypass guard stays green.
# Same prerequisites as e2e-core.
e2e-phase3:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase3_orchestration.py -p no:cacheprovider --no-cov
	uv run pytest runtime/tests/test_bypass.py runtime/tests/test_audit_hook.py -q -p no:cacheprovider --no-cov

# Phase 4 exit: an agent uses memory, MCP (stdio + inbound), sandboxed code and a real-Chromium browser in real runs through the
# real Risk Kernel (gRPC) and the Postgres audit chain; every call has a decision row; DENY, ACL, tenancy, kill-switch and
# prompt-injection scenarios; then the bypass guard stays green. Same prerequisites as e2e-core, plus unprivileged user
# namespaces (the sandbox refuses to run otherwise: the e2e FAILS, it never skips) and the Playwright Chromium build.
e2e-phase4:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase4_tools.py -p no:cacheprovider --no-cov
	uv run pytest runtime/tests/test_bypass.py runtime/tests/test_audit_hook.py runtime/tests/test_mcp_bypass.py -q -p no:cacheprovider --no-cov

# Phase 5 exit: ONE agent (one ABL blueprint) answers on web, Slack, SMS and email and over voice; conversation continuity for a linked
# identity and isolation for unlinked ones; forged / replayed / unrouted webhooks rejected and audited with no run; cross-tenant routing
# impossible; every outbound message and call decided by the real Risk Kernel (DENY / kill-switch send nothing); PHI transcripts redacted
# before persistence; transcripts (hashes + sizes) in the tenant's Postgres audit chain on one trace per turn / call; then the bypass
# guard stays green. Same prerequisites as e2e-core. Fakes: provider transports, the LLM, STT/TTS vendors, the telephony gateway.
e2e-phase5:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase5_channels.py -p no:cacheprovider --no-cov
	uv run pytest runtime/tests/test_bypass.py runtime/tests/test_audit_hook.py -q -p no:cacheprovider --no-cov

# Phase 6 exit: a new tenant signs up via SSO (fake IdP), the admin configures a BYO model key, a policy pack and a budget over the
# control-plane HTTP API, an agent runs through the real Risk Kernel with THAT tenant's activated policy (a DENY from the tenant's
# pack is enforced), the key comes from the control plane (HttpSecretStore), the tenant's budgets are enforced by TKI, usage is
# metered into the billing ledger and equals totals recomputed independently from the audit chain and the run log, period close +
# seal + invoice + Stripe-fake reconciliation are clean, injected provider faults are reported and never silently fixed; RBAC,
# cross-tenant admin attacks, API key scopes, SCIM deprovisioning, region pinning, live-key refusal, replayed/forged usage and
# dedicated-database routing are exercised; then the bypass guard stays green. Same prerequisites as e2e-core (two databases are created).
e2e-phase6:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase6_saas.py -p no:cacheprovider --no-cov
	uv run pytest runtime/tests/test_bypass.py runtime/tests/test_audit_hook.py -q -p no:cacheprovider --no-cov

# Phase 7 exit (interfaces): every core workflow through the TypeScript SDK, the Python SDK and the `axis` CLI against the REAL stack
# (Postgres 16, the real Risk Kernel over gRPC, control plane, billing, registry/marketplace, AGIL, the Python run service with a scripted
# model, and the API gateway as a standalone process): signup, policy activate, blueprint, signed registry publish + verified resolve,
# marketplace install with consent, run + SSE + replay, approve / deny, audit verify + tamper detection, AGIL explanations, usage ==
# ledger, kill-switch, then cross-tenant and API-key-scope checks; then the bypass guard stays green. The console is covered by
# `make console-e2e` on the same stack. Same prerequisites as e2e-core.
e2e-phase7:
	pnpm build
	bash infra/scripts/with-pg.sh uv run pytest e2e/test_phase7_interfaces.py -p no:cacheprovider --no-cov
	uv run pytest runtime/tests/test_bypass.py runtime/tests/test_audit_hook.py -q -p no:cacheprovider --no-cov

# Everything Phase 7 adds on top of the core loops: the three non-browser clients, then the console (Playwright) on the real stack.
e2e: e2e-phase7 console-e2e

evals:
	@echo "(planned) Phase 8: Eval Hub suites"; exit 1

# Compiles policies/**, checks Rego (opa check --strict), proves Wasm builds, runs generated `opa test` cases. Needs `opa` (>= 0.70) on PATH.
policy-test:
	pnpm --filter @axis/policy exec tsx src/cli.ts test ../../policies
	pnpm --filter @axis/policy exec tsx src/cli.ts test ../../e2e/policies

k3s-up:
	@echo "(planned) Phase 10"; exit 1

tf-plan:
	@echo "(planned) Phase 10: plan only, never apply"; exit 1

# Regenerate the TS/Python SDK layers from the OpenAPI (ADR 0040); drift tests run --check.
sdk-generate:
	node scripts/generate-sdks.mjs

# Mutation check of SDK/CLI safety logic (ADR 0043).
sdk-mutation:
	node scripts/mutation-sdk.mjs

# Phase 7 / D: console build (with a dev-login flag), client-bundle secret scan, then the Playwright suite against
# the mock control-plane API. Needs Playwright's Chromium (PLAYWRIGHT_BROWSERS_PATH) and nothing else.
console-e2e:
	pnpm --filter @axis/abl --filter @axis/contracts build
	cd apps/console && NEXT_PUBLIC_DEV_LOGIN=1 AXIS_API_URL=http://127.0.0.1:4010 NEXT_TELEMETRY_DISABLED=1 pnpm exec next build
	cd apps/console && AXIS_SCAN_SENTINELS=127.0.0.1:4010 node scripts/scan-bundle.mjs .next/static
	cd apps/console && AXIS_API_URL=http://127.0.0.1:4010 pnpm exec playwright test

docs-build:
	pnpm --filter @axis/docs-site build
