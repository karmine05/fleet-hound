#!/usr/bin/env bash
# Create the first Memgraph user (Community auth) if credentials are set
# and no users exist yet. First CREATE USER becomes a superuser and from
# that moment Bolt requires those credentials.
#
# Safe to run repeatedly: SHOW USERS with the configured login is a no-op
# once the user exists. If SHOW USERS without auth succeeds and returns
# rows, we do nothing (another user already owns the instance).
set -euo pipefail

HOST="${MEMGRAPH_HOST:-127.0.0.1}"
PORT="${MEMGRAPH_BOLT_PORT:-7687}"
USER="${MEMGRAPH_USER:-}"
PASS="${MEMGRAPH_PASSWORD:-}"

if [[ -z "$USER" || -z "$PASS" ]]; then
    echo "memgraph-auth: MEMGRAPH_USER/PASSWORD unset; leaving Bolt userless"
    exit 0
fi
# The first user becomes the superuser: never create it with the example value.
if [[ "$PASS" == "change-me" ]]; then
    echo "memgraph-auth: MEMGRAPH_PASSWORD is the .env.example placeholder; set one with: openssl rand -hex 24" >&2
    exit 1
fi
# USER is interpolated into Cypher below, so it must be a plain identifier.
if [[ ! "$USER" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "memgraph-auth: MEMGRAPH_USER must match [A-Za-z_][A-Za-z0-9_]*" >&2
    exit 1
fi

# Unauthenticated mgconsole; stdin = cypher. The authenticated check below
# passes the password in the FLAGS_password env var (mgconsole --fromenv),
# never in a process argv.
mg() {
    docker exec -i fleet-memgraph mgconsole \
        --host "$HOST" --port "$PORT" --use-ssl=false
}

# Already authenticated as the configured user?
if echo "RETURN 1;" | FLAGS_password="$PASS" \
        docker exec -i -e FLAGS_password fleet-memgraph mgconsole \
        --host "$HOST" --port "$PORT" --use-ssl=false \
        --username="$USER" --fromenv=password &>/dev/null; then
    echo "memgraph-auth: user ${USER} already works"
    exit 0
fi

# Userless instance: CREATE USER is allowed and becomes the first superuser.
if echo "SHOW USERS;" | mg &>/dev/null; then
    # Cypher string literal: escape backslashes first, then single quotes.
    cypher_pass="${PASS//\\/\\\\}"
    cypher_pass="${cypher_pass//\'/\\\'}"
    if echo "CREATE USER IF NOT EXISTS ${USER} IDENTIFIED BY '${cypher_pass}';" | mg >/dev/null; then
        echo "memgraph-auth: created first user ${USER}"
        exit 0
    fi
    echo "memgraph-auth: CREATE USER failed" >&2
    exit 1
fi

echo "memgraph-auth: Bolt requires auth but ${USER} was rejected" >&2
exit 1
