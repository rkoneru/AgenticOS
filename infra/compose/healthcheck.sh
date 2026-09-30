#!/usr/bin/env bash
# Probes every dev-stack endpoint from the host. Exits non-zero on the first failure.
set -u
fail=0
check() { # name, command...
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}
check postgres      docker compose -f infra/compose/docker-compose.yml exec -T postgres pg_isready -U axis
check redis         docker compose -f infra/compose/docker-compose.yml exec -T redis redis-cli ping
check clickhouse    curl -fsS http://localhost:8123/ping
check temporal-ui   curl -fsS http://localhost:8233/
check opa           curl -fsS http://localhost:8181/health
check jaeger        curl -fsS http://localhost:16686/
check grafana       curl -fsS http://localhost:3001/api/health
check otel-http     curl -sS -o /dev/null -w '%{http_code}' -X POST http://localhost:4318/v1/traces -H 'content-type: application/json' -d '{}'
exit $fail
