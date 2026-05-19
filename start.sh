#!/usr/bin/env bash
# Fleet Hound start script.
#
# Brings up Memgraph + webviz, waits for both to report healthy, and surfaces
# the OODA supervisor's view so the operator can confirm autonomy is wired up.
#
# Usage:
#   ./start.sh              # boot stack, do not run host-side ETL
#   ./start.sh --full-scan  # boot stack, then run a one-shot host ETL with the args passed through
#   FOLLOW_LOGS=1 ./start.sh   # keep tailing logs after boot

set -euo pipefail

cd "$(dirname "$0")"

# Auto-activate virtual environment if it exists
if [[ -d venv ]]; then
    source venv/bin/activate
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}ℹ️  $*${NC}"; }
ok()    { echo -e "${GREEN}✅ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $*${NC}"; }
fail()  { echo -e "${RED}❌ $*${NC}"; }

echo "🩸 Fleet Hound"
echo "=============================================="

# --- Tooling preflight ------------------------------------------------------
if ! command -v docker &>/dev/null; then
    fail "Docker is not installed."; exit 1
fi
if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE=(docker-compose)
else
    fail "Docker Compose is not installed."; exit 1
fi
ok "Docker + Compose detected"

# --- .env preflight ---------------------------------------------------------
if [[ ! -f .env ]]; then
    if [[ -f .env.example ]]; then
        warn ".env not found. Copy .env.example to .env and fill in FLEET_URL + FLEET_API_TOKEN before continuing."
    else
        fail ".env not found and no .env.example to copy from."
    fi
    exit 1
fi

# Read a small set of values from .env without exporting the whole file. Lets
# us tell the operator what's about to happen and gate the OODA status check.
read_env() {
    awk -F= -v k="$1" '$0 !~ /^[[:space:]]*#/ && $1==k {sub(/^[^=]*=/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit}' .env
}
WEBVIZ_API_TOKEN_VAL="$(read_env WEBVIZ_API_TOKEN || true)"
OODA_ENABLED_VAL="$(read_env OODA_ENABLED || true)"
PORT_VAL="$(read_env PORT || echo 8080)"
PORT_VAL="${PORT_VAL:-8080}"
BASE_URL="http://127.0.0.1:${PORT_VAL}"

if [[ -z "${WEBVIZ_API_TOKEN_VAL}" ]]; then
    warn "WEBVIZ_API_TOKEN is empty — /api/* GETs will be loopback-only and OODA status check will be skipped."
fi

# --- Boot the stack ---------------------------------------------------------
info "Building + starting containers..."
"${DOCKER_COMPOSE[@]}" up -d --build

# --- Wait for Memgraph -----------------------------------------------------
info "Waiting for Memgraph (Bolt 7687)..."
for i in $(seq 1 60); do
    if echo "RETURN 1;" | docker exec -i fleet-memgraph mgconsole --host 127.0.0.1 --port 7687 --use-ssl=false &>/dev/null; then
        ok "Memgraph is ready"
        break
    fi
    [[ $i -eq 60 ]] && { fail "Memgraph did not become ready. Check: ${DOCKER_COMPOSE[*]} logs memgraph"; exit 1; }
    sleep 2
done

# --- Wait for webviz -------------------------------------------------------
info "Waiting for webviz (HTTP $BASE_URL/api/health)..."
for i in $(seq 1 30); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" 2>/dev/null || echo 000)"
    case "$code" in
        200) ok "webviz is healthy"; break ;;
        503) ok "webviz is up (Memgraph ping warming)"; break ;;
    esac
    [[ $i -eq 30 ]] && { fail "webviz did not respond. Check: ${DOCKER_COMPOSE[*]} logs webviz"; exit 1; }
    sleep 2
done

# --- OODA supervisor status -----------------------------------------------
# /api/ooda/status is auth-gated when WEBVIZ_API_TOKEN is set. Skip the check
# if the operator hasn't configured a token (status is reachable from inside
# the container; surfacing it here is purely informational).
if [[ -n "${WEBVIZ_API_TOKEN_VAL}" ]]; then
    info "Checking OODA supervisor..."
    ooda_json="$(curl -sS -H "Authorization: Bearer ${WEBVIZ_API_TOKEN_VAL}" \
                       "$BASE_URL/api/ooda/status" 2>/dev/null || true)"
    if [[ -n "$ooda_json" ]] && command -v python3 &>/dev/null; then
        printf '%s' "$ooda_json" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
state = "ENABLED" if d.get("enabled") else "DISABLED"
running = "running" if d.get("running") else "idle"
interval = d.get("interval_sec", "?")
full_scan = d.get("full_scan_every", "?")
total = d.get("cycles_total", 0)
failed = d.get("cycles_failed", 0)
print(
    f"   OODA: {state}, leader={running}, "
    f"interval={interval}s, full-scan-every={full_scan} cycles, "
    f"cycles_total={total}, cycles_failed={failed}"
)
'
    fi
    ok "Stack reachable"
fi

# --- Optional: pass-through to host CLI -----------------------------------
if [[ $# -gt 0 ]]; then
    echo
    info "Running host-side ETL: python3 main.py $*"
    if ! python3 main.py "$@"; then
        warn "Host ETL exited non-zero. The container OODA loop will keep running."
    fi
fi

# --- Banner -----------------------------------------------------------------
echo
echo "=============================================="
ok "Fleet Hound is up"
echo "=============================================="
echo "  Dashboard:        $BASE_URL"
echo "  OODA status:      $BASE_URL/api/ooda/status   (Bearer \$WEBVIZ_API_TOKEN)"
echo "  OODA findings:    $BASE_URL/api/ooda/findings"
echo "  OODA cycles:      $BASE_URL/api/ooda/cycles"
echo "  Trigger cycle:    POST $BASE_URL/api/ooda/trigger   (60s cooldown)"
echo "  Memgraph Bolt:    bolt://localhost:7687"
echo
echo "  Logs:             ${DOCKER_COMPOSE[*]} logs -f"
echo "  Stop:             ./stop.sh"
echo "  Wipe DB:          python3 clear_db.py --yes"
echo

if [[ "${OODA_ENABLED_VAL:-false}" =~ ^([Tt]rue|1|[Yy]es|on)$ ]]; then
    info "OODA_ENABLED=true — webviz will drive ETL cycles autonomously."
    info "If this is the very first run, the first cycle will behave like --full-scan."
else
    warn "OODA_ENABLED is not true. Run host ETL manually with: python3 main.py"
fi

if [[ "${FOLLOW_LOGS:-0}" == "1" ]]; then
    echo
    info "Tailing logs (Ctrl+C to stop)..."
    "${DOCKER_COMPOSE[@]}" logs -f
fi
