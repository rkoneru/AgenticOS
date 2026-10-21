#!/usr/bin/env bash
# Verifies NEEDS #518's fix: `helm template` of each chart that renders a ConfigMap/Secret
# produces a different pod-template checksum/config or checksum/secret annotation when that
# ConfigMap/Secret's rendered data changes — proving `helm upgrade` would actually roll the pods
# on a values-only secret/config change, instead of silently leaving stale pods running.
#
# Usage: infra/helm/scripts/verify-checksum-rollout.sh (run from the repo root; needs `helm` on PATH)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

fail=0

check() {
  local chart="$1" set_a="$2" set_b="$3" grep_for="$4"
  local before after
  before="$(helm template t "infra/helm/charts/$chart" --set "$set_a" 2>/dev/null | grep "$grep_for" || true)"
  after="$(helm template t "infra/helm/charts/$chart" --set "$set_b" 2>/dev/null | grep "$grep_for" || true)"
  if [ -z "$before" ] || [ -z "$after" ]; then
    echo "FAIL  $chart: no '$grep_for' annotation rendered at all"
    fail=1
  elif [ "$before" = "$after" ]; then
    echo "FAIL  $chart: $grep_for did not change when the underlying data did"
    fail=1
  else
    echo "OK    $chart: $grep_for changes with the chart's rendered Secret/ConfigMap data"
  fi
}

# Secret-backed charts (shared values shape: secret.data.<KEY>)
for chart in api-gateway billing channels compliance console control-plane data-governance \
             eval-hub marketplace memory registry risk-kernel; do
  check "$chart" "secret.data.VERIFY_PROBE=aaaa" "secret.data.VERIFY_PROBE=bbbb" "checksum/secret"
done

# ConfigMap-backed charts (shared values shape: config.<KEY>)
for chart in api-gateway billing channels compliance console control-plane data-governance \
             eval-hub marketplace memory registry risk-kernel; do
  check "$chart" "config.VERIFY_PROBE=aaaa" "config.VERIFY_PROBE=bbbb" "checksum/config"
done

# runtime's run-server uses its own configmap values shape
check "runtime" "runServer.config.VERIFY_PROBE=aaaa" "runServer.config.VERIFY_PROBE=bbbb" "checksum/config"

if [ "$fail" -ne 0 ]; then
  echo
  echo "verify-checksum-rollout: FAILED"
  exit 1
fi
echo
echo "verify-checksum-rollout: all charts roll pods on a Secret/ConfigMap data change"
