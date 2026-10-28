#!/usr/bin/env bash
# Fleet Hound start script.
#
# Brings up Memgraph + webviz, waits for both to report healthy, and surfaces
# the OODA supervisor's view so the operator can confirm autonomy is wired up.
#
# Docker is the only supported deployment. Every Python command runs inside
# the webviz container, never against a host virtualenv.
#
# Usage:
#   ./start.sh              # boot stack, leave ETL to the OODA supervisor
#   ./start.sh --full-scan  # boot stack, then run one ETL pass inside webviz
#   FOLLOW_LOGS=1 ./start.sh   # keep tailing logs after boot

set -euo pipefail

cd "$(dirname "$0")"

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
# No `exit` on first match: Compose lets a later duplicate key win, so the
# helper has to agree with it.
read_env() {
    awk -F= -v k="$1" '$0 !~ /^[[:space:]]*#/ && $1==k {sub(/^[^=]*=/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); v=$0} END {print v}' .env
}
WEBVIZ_API_TOKEN_VAL="$(read_env WEBVIZ_API_TOKEN || true)"
WEBVIZ_API_TOKEN_FILE_VAL="$(read_env WEBVIZ_API_TOKEN_FILE || true)"
WEBVIZ_REQUIRE_AUTH_VAL="$(read_env WEBVIZ_REQUIRE_AUTH || true)"
OODA_ENABLED_VAL="$(read_env OODA_ENABLED || true)"
# docker-compose.yml pins the published port to 8080 on loopback.
BASE_URL="http://127.0.0.1:8080"
MEMGRAPH_USER_VAL="$(read_env MEMGRAPH_USER || true)"
MEMGRAPH_PASSWORD_VAL="$(read_env MEMGRAPH_PASSWORD || true)"

mg_ready() {
    if [[ -n "${MEMGRAPH_USER_VAL}" && -n "${MEMGRAPH_PASSWORD_VAL}" ]]; then
        # Password via FLAGS_password (mgconsole --fromenv), never in an argv.
        echo "RETURN 1;" | FLAGS_password="${MEMGRAPH_PASSWORD_VAL}" \
            docker exec -i -e FLAGS_password fleet-memgraph mgconsole \
            --host 127.0.0.1 --port 7687 --use-ssl=false \
            --username="${MEMGRAPH_USER_VAL}" --fromenv=password \
            &>/dev/null && return 0
    fi
    echo "RETURN 1;" | docker exec -i fleet-memgraph mgconsole \
        --host 127.0.0.1 --port 7687 --use-ssl=false &>/dev/null
}

# The image is fail-closed (WEBVIZ_REQUIRE_AUTH=true): with no token, webviz
# exits at boot and restarts forever. Stop here with the real reason.
if [[ -z "${WEBVIZ_API_TOKEN_VAL}" && -z "${WEBVIZ_API_TOKEN_FILE_VAL}" \
      && "$(printf '%s' "${WEBVIZ_REQUIRE_AUTH_VAL}" | tr '[:upper:]' '[:lower:]')" != "false" ]]; then
    fail "WEBVIZ_API_TOKEN is required (the image sets WEBVIZ_REQUIRE_AUTH=true). Generate one with: openssl rand -hex 32"
    exit 1
fi
# The first Memgraph user becomes the superuser: never bootstrap it with the
# example value.
if [[ "${MEMGRAPH_PASSWORD_VAL}" == "change-me" ]]; then
    fail "MEMGRAPH_PASSWORD is the .env.example placeholder. Set one with: openssl rand -hex 24"
    exit 1
fi

# --- Boot the stack ---------------------------------------------------------
info "Building images..."
"${DOCKER_COMPOSE[@]}" build

# ./config is bind-mounted over /app/config, hiding the image's chown. Docker
# Desktop (macOS) remaps ownership; a Linux host does not, so give the mount
# to the container user (uid 10001). Plain `docker run`, because compose's
# cap_drop: ALL removes CAP_CHOWN. busybox, because the distroless app image
# ships no chown.
if [[ "$(uname -s)" == "Linux" ]]; then
    info "Giving ./config to the container user (uid 10001)..."
    docker run --rm --user 0 -v "$PWD/config:/app/config" \
        busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 \
        chown -R 10001:10001 /app/config
fi

info "Starting containers..."
"${DOCKER_COMPOSE[@]}" up -d

# --- Wait for Memgraph -----------------------------------------------------
info "Waiting for Memgraph (Bolt 7687)..."
for i in $(seq 1 60); do
    if mg_ready; then
        ok "Memgraph is ready"
        break
    fi
    [[ $i -eq 60 ]] && { fail "Memgraph did not become ready. Check: ${DOCKER_COMPOSE[*]} logs memgraph"; exit 1; }
    sleep 2
done

if [[ -n "${MEMGRAPH_USER_VAL}" && -n "${MEMGRAPH_PASSWORD_VAL}" ]]; then
    info "Ensuring Memgraph Bolt user ${MEMGRAPH_USER_VAL}..."
    MEMGRAPH_USER="${MEMGRAPH_USER_VAL}" MEMGRAPH_PASSWORD="${MEMGRAPH_PASSWORD_VAL}" \
        bash ./scripts/ensure_memgraph_user.sh
fi

# --- Wait for webviz -------------------------------------------------------
info "Waiting for webviz (HTTP $BASE_URL/api/health)..."
for i in $(seq 1 30); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" 2>/dev/null || echo 000)"
    case "$code" in
        200) ok "webviz is healthy"; break ;;
    esac
    # 503 means webviz is up but cannot reach Memgraph (e.g. Bolt auth mismatch).
    [[ $i -eq 30 ]] && { fail "webviz not healthy (last HTTP $code). Check: ${DOCKER_COMPOSE[*]} logs webviz"; exit 1; }
    sleep 2
done

# --- Fleet team scope ------------------------------------------------------
# ETL never scans every team by default. If OODA_TEAMS is unset, list the
# teams from Fleet, ask once, and persist the choice to .env.
OODA_TEAMS_VAL="$(read_env OODA_TEAMS || true)"
if [[ -z "${OODA_TEAMS_VAL}" ]]; then
    if [[ -t 0 ]]; then
        info "No Fleet teams selected (OODA_TEAMS). Fetching team list..."
        "${DOCKER_COMPOSE[@]}" exec -T webviz fleethound etl --list-teams || warn "Could not list teams (check FLEET_URL / FLEET_API_TOKEN)."
        while [[ -z "${OODA_TEAMS_VAL}" ]]; do
            read -r -p "Team IDs to scan (comma-separated): " picked
            picked="${picked// /}"
            if [[ "$picked" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
                OODA_TEAMS_VAL="$picked"
            else
                warn "Enter one or more integer team IDs, e.g. 1,2"
            fi
        done
        if grep -qE '^[[:space:]]*OODA_TEAMS=' .env; then
            sed -i.bak -E "s/^[[:space:]]*OODA_TEAMS=.*/OODA_TEAMS=${OODA_TEAMS_VAL}/" .env && rm -f .env.bak
        else
            printf '\nOODA_TEAMS=%s\n' "${OODA_TEAMS_VAL}" >> .env
        fi
        ok "Saved OODA_TEAMS=${OODA_TEAMS_VAL} to .env; restarting webviz to pick it up"
        "${DOCKER_COMPOSE[@]}" up -d webviz
        for i in $(seq 1 30); do
            [[ "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" 2>/dev/null || echo 000)" == 200 ]] && break
            sleep 2
        done
    else
        warn "OODA_TEAMS is empty. ETL and OODA will refuse to run until you set Fleet team IDs in .env."
    fi
else
    ok "Fleet team scope: OODA_TEAMS=${OODA_TEAMS_VAL}"
fi

# --- OODA supervisor status -----------------------------------------------
# /api/ooda/status is auth-gated when WEBVIZ_API_TOKEN is set. Skip the check
# if the operator hasn't configured a token (status is reachable from inside
# the container; surfacing it here is purely informational).
if [[ -n "${WEBVIZ_API_TOKEN_VAL}" ]]; then
    info "Checking OODA supervisor..."
    ooda_json="$(curl -sS -H "Authorization: Bearer ${WEBVIZ_API_TOKEN_VAL}" \
                       "$BASE_URL/api/ooda/status" 2>/dev/null || true)"
    if [[ "$ooda_json" == \{* ]]; then
        # shortcut: first-match scalar lookup, fine for these flat top-level keys
        # (none recur under last_cycle); use jq if the status payload grows.
        ooda_field() {
            local m
            m="$(printf '%s' "$ooda_json" | grep -o "\"$1\":[^,}]*" | head -n 1 || true)"
            m="${m#*:}"
            printf '%s' "${m:-$2}"
        }
        state=DISABLED; [[ "$(ooda_field enabled false)" == true ]] && state=ENABLED
        running=idle; [[ "$(ooda_field running false)" == true ]] && running=running
        echo "   OODA: ${state}, leader=${running}, interval=$(ooda_field interval_sec '?')s," \
             "full-scan-every=$(ooda_field full_scan_every '?') cycles," \
             "cycles_total=$(ooda_field cycles_total 0), cycles_failed=$(ooda_field cycles_failed 0)"
    fi
    ok "Stack reachable"
fi

# --- Optional: one ETL pass inside the container ---------------------------
if [[ $# -gt 0 ]]; then
    echo
    info "Running ETL in the webviz container: fleethound etl $*"
    if ! "${DOCKER_COMPOSE[@]}" exec -T webviz fleethound etl "$@"; then
        warn "ETL exited non-zero. The container OODA loop will keep running."
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
echo "  Wipe DB:          ${DOCKER_COMPOSE[*]} exec webviz fleethound clear-db --yes"
echo
echo "  ETL (one pass):   ${DOCKER_COMPOSE[*]} exec -T webviz fleethound etl"
echo "  ETL (full):       ${DOCKER_COMPOSE[*]} exec -T webviz fleethound etl --full-scan"
echo

if [[ "${OODA_ENABLED_VAL:-false}" =~ ^([Tt]rue|1|[Yy]es|on)$ ]]; then
    info "OODA_ENABLED=true — webviz will drive ETL cycles autonomously."
    info "If this is the very first run, the first cycle will behave like --full-scan."
else
    warn "OODA_ENABLED is not true. Run one pass with: ${DOCKER_COMPOSE[*]} exec -T webviz fleethound etl"
fi

if [[ "${FOLLOW_LOGS:-0}" == "1" ]]; then
    echo
    info "Tailing logs (Ctrl+C to stop)..."
    "${DOCKER_COMPOSE[@]}" logs -f
fi
