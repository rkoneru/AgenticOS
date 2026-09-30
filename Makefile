.PHONY: e2e-core contracts-lint freeze install dev dev-down dev-ps dev-health test e2e cov evals lint typecheck policy-test k3s-up tf-plan fmt
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
	bash infra/scripts/with-pg.sh uv run pytest e2e -p no:cacheprovider --no-cov

# (Phase 7) Playwright console + CLI e2e
e2e:
	@echo "(planned) Phase 7: Playwright + CLI e2e"; exit 1

evals:
	@echo "(planned) Phase 8: Eval Hub suites"; exit 1

# Compiles policies/**, checks Rego (opa check --strict), proves Wasm builds, runs generated `opa test` cases. Needs `opa` (>= 0.70) on PATH.
policy-test:
	pnpm --filter @axis/policy exec tsx src/cli.ts test ../../policies

k3s-up:
	@echo "(planned) Phase 10"; exit 1

tf-plan:
	@echo "(planned) Phase 10: plan only, never apply"; exit 1
