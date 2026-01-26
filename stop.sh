#!/usr/bin/env bash

# Fleet Hound Stop Script
# This script stops the services

set -euo pipefail

echo "🩸 Stopping Fleet Hound Services..."
echo ""

# Determine docker compose command
if docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE=(docker compose)
else
    DOCKER_COMPOSE=(docker-compose)
fi

# Stop services
"${DOCKER_COMPOSE[@]}" down

echo ""
echo "✅ All services stopped successfully!"
echo ""
echo "To start again, run: ./start.sh"
echo "To remove all data, run: ${DOCKER_COMPOSE[*]} down -v"

