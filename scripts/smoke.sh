#!/usr/bin/env bash
# Fleet Hound post-deploy smoke test.
#
# Hits the dashboard's public endpoints and records pass/fail per check.
# Exits non-zero on any hard failure so a pipeline can fail-fast.
#
# Usage:
#   ./scripts/smoke.sh                              # against http://127.0.0.1:8080
#   FH_BASE=https://fh.example ./scripts/smoke.sh
#   FH_TOKEN=xyz ./scripts/smoke.sh                 # exercise authed routes too

set -uo pipefail

BASE="${FH_BASE:-http://127.0.0.1:8080}"
TOKEN="${FH_TOKEN:-}"
PASS=0
FAIL=0

check() {
  local name="$1"; shift
  local expected_code="$1"; shift
  local code
  code="$(curl -sS -o /tmp/fh-smoke.body -w '%{http_code}' "$@" || true)"
  if [[ "$code" == "$expected_code" ]]; then
    echo "  ok   $name (HTTP $code)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL $name (got HTTP $code, want $expected_code)"
    sed -e 's/^/       | /' /tmp/fh-smoke.body | head -3
    FAIL=$((FAIL + 1))
  fi
}

echo "Smoke testing $BASE"
echo

# Healthcheck must always answer (200 healthy / 503 db-down). Either is
# acceptable here — we only fail on transport errors / 5xx-with-body.
hc_code="$(curl -sS -o /tmp/fh-smoke.body -w '%{http_code}' "$BASE/api/health" || echo 000)"
case "$hc_code" in
  200|503) echo "  ok   GET /api/health (HTTP $hc_code)"; PASS=$((PASS + 1)) ;;
  *)       echo "  FAIL GET /api/health (HTTP $hc_code)"; FAIL=$((FAIL + 1)) ;;
esac

# A read endpoint should reflect the auth posture.
if [[ -n "$TOKEN" ]]; then
  check "GET /api/teams (with token)" 200 -H "Authorization: Bearer $TOKEN" "$BASE/api/teams"
  check "GET /api/meta (with token)"  200 -H "Authorization: Bearer $TOKEN" "$BASE/api/meta"
  # Wrong token must be rejected.
  check "GET /api/teams (bad token)"  401 -H "Authorization: Bearer wrong" "$BASE/api/teams"
  # Invalid regex must be blocked before DB.
  check "GET /api/search ReDoS guard" 400 -H "Authorization: Bearer $TOKEN" \
    --data-urlencode "mode=regex" --data-urlencode "q=(a+)+" -G "$BASE/api/search"
  # OODA endpoints answer regardless of OODA_ENABLED — they expose status.
  check "GET /api/ooda/status"        200 -H "Authorization: Bearer $TOKEN" "$BASE/api/ooda/status"
  check "GET /api/enricher/status"    200 -H "Authorization: Bearer $TOKEN" "$BASE/api/enricher/status"
else
  echo "  skip token-required routes (set FH_TOKEN to enable)"
fi

# Static index is always served.
check "GET /" 200 "$BASE/"

echo
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
