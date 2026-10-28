#!/usr/bin/env bash
# Fleet Hound stop script.
#
# Default: graceful shutdown (containers stopped, volumes preserved).
# --purge: also drop the Memgraph data volume AND clean host-side / bind-mount
#          state (./config/.state.json, ./config/snapshots/, ./config/whitelist.json,
#          ./.state.json, ./.etl.lock). Use only when you want a fully empty
#          deployment on the next ./start.sh.

set -euo pipefail

cd "$(dirname "$0")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${BLUE}ℹ️  $*${NC}"; }
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
fail() { echo -e "${RED}❌ $*${NC}"; }

if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE=(docker-compose)
else
    fail "Docker Compose is not installed."; exit 1
fi

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            cat <<USAGE
./stop.sh [--purge [--yes]]

  (default)   Stop containers. Memgraph volume + /app/config artifacts kept.
  --purge     Also drop the Memgraph data volume AND wipe host-side runtime
              state (./config/.state.json, ./config/snapshots/,
              ./config/whitelist.json, ./.state.json, ./.etl.lock).
              NEXT ./start.sh boots with no carry-over. Asks for confirmation;
              the audit log is kept as ./config/audit.log.purged-<timestamp>.
  --yes       Skip the --purge confirmation (for scripts).
USAGE
            exit 0
            ;;
        --purge) PURGE=1 ;;
        --yes)   ASSUME_YES=1 ;;
        *)       fail "Unknown argument: $arg"; exit 2 ;;
    esac
done

echo "🩸 Stopping Fleet Hound..."

# OODA supervisor cycles can be in-flight inside webviz. The compose stop
# below sends SIGTERM and waits up to graceful_timeout (30s in Dockerfile)
# for in-flight queries to drain. The fcntl lock on /tmp is freed on exit
# so a fresh start.sh re-elects a leader cleanly.
if [[ "$PURGE" -eq 1 && "$ASSUME_YES" -ne 1 ]]; then
    warn "Purge drops the graph, the operator allowlist (whitelist.json) and all runtime state."
    read -r -p "Type PURGE to confirm: " answer
    [[ "$answer" == "PURGE" ]] || { fail "Aborted"; exit 1; }
fi

if [[ "$PURGE" -eq 1 ]]; then
    warn "Purging Memgraph volume — graph data will be lost."
    "${DOCKER_COMPOSE[@]}" down -v

    # The audit trail is evidence, not state: keep it under a dated name.
    if [[ -e ./config/audit.log ]]; then
        kept="./config/audit.log.purged-$(date -u +%Y%m%dT%H%M%SZ)"
        mv ./config/audit.log "$kept"
        ok "  kept audit log as $kept"
    fi

    # `docker compose down -v` removes named volumes only. The webviz service
    # bind-mounts ./config:/app/config (see docker-compose.yml), so anything
    # the OODA/enrichment workers wrote into /app/config survives `down -v`
    # and gets re-loaded on the next start. Wipe those explicitly here.
    #
    # Preserves ./config/memgraph.conf — that's config, not state.
    purge_paths=(
        # Legacy host-side state (pre-Docker runs). Kept so an old checkout
        # purges completely; current ETL runs inside the container.
        "./.state.json"
        "./.etl.lock"
        # Container-side runtime state (bind-mounted from ./config).
        "./config/.state.json"
        "./config/whitelist.json"
        "./config/snapshots"
        "./config/ooda_status.json"
        "./config/ooda_findings.json"
        "./config/ooda_cycles.jsonl"
        "./config/enricher_status.json"
        "./config/extension_status.json"
        "./config/extension_cache"
        "./config/.etl.lock"
    )
    removed=0
    for p in "${purge_paths[@]}"; do
        if [[ -e "$p" ]]; then
            rm -rf -- "$p"
            ok "  removed $p"
            removed=$((removed + 1))
        fi
    done
    if [[ "$removed" -eq 0 ]]; then
        info "  no host-side state artifacts to remove"
    fi
else
    info "Stopping containers (volumes preserved)..."
    "${DOCKER_COMPOSE[@]}" stop
    "${DOCKER_COMPOSE[@]}" down --remove-orphans
fi

ok "Stack stopped"
echo
if [[ "$PURGE" -eq 1 ]]; then
    info "Volumes + host-side state were dropped. ./start.sh --full-scan re-baselines, or the OODA loop's first cycle does it automatically."
else
    info "Volumes preserved."
    info "  Restart:        ./start.sh"
    info "  Wipe data:      ./stop.sh --purge   (or: docker compose exec -T webviz fleethound clear-db --yes while running)"
fi
