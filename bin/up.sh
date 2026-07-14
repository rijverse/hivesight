#!/usr/bin/env bash
# bin/up.sh — one-shot launcher for the honeypot stack.
#
# What it does:
#   1. Preflight: bind-mount source dirs, .env file, port collisions.
#   2. Sync every dashboards/*.json into the Grafana provisioning folder so a
#      fresh stack still ships with the current dashboards.
#   3. `docker compose up -d` with both compose files.
#   4. Wait for the orchestrator and grafana to be healthy, then print URLs.
#
# Usage:
#   bin/up.sh           # full start
#   bin/up.sh --stop    # docker compose down
#   bin/up.sh --reset   # down + delete named volumes (DESTROYS data)
#   bin/up.sh --pull    # pull images before up

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="up"
PULL=0
for arg in "$@"; do
    case "$arg" in
        --stop) MODE="stop" ;;
        --reset) MODE="reset" ;;
        --pull) PULL=1 ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose-ai-av.yml)

preflight() {
    command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
    docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 1; }
    docker compose version >/dev/null 2>&1 || { echo "docker compose plugin not found" >&2; exit 1; }

    # bind-mount source dirs
    mkdir -p orchestrator-data

    # sync all dashboards into provisioning
    mkdir -p grafana-provisioning/dashboards/files
    cp -f dashboards/*.json grafana-provisioning/dashboards/files/

    # port-collision warning (informational; compose will still fail clearly)
    for p in 22 3000; do
        if ss -ltn "sport = :$p" 2>/dev/null | tail -n +2 | grep -q LISTEN; then
            echo "warning: host port $p is already in use" >&2
        fi
    done
}

do_stop() {
    "${COMPOSE[@]}" down
}

do_reset() {
    "${COMPOSE[@]}" down -v
    echo "all hivesight named volumes deleted"
}

do_up() {
    preflight
    if (( PULL )); then
        "${COMPOSE[@]}" pull --ignore-pull-failures || true
    fi
    "${COMPOSE[@]}" up -d
    echo "installing egress block..."
    if ! sh "$ROOT/egress-block.sh"; then
        echo "warning: egress block failed (not root?); honeypots can reach the internet" >&2
    fi
    echo "waiting for grafana health..."
    for i in {1..40}; do
        status=$(docker inspect --format='{{.State.Health.Status}}' grafana 2>/dev/null || echo starting)
        if [[ "$status" == "healthy" ]]; then break; fi
        sleep 2
    done
    echo "done."
    echo "  Grafana:    http://localhost:3000  (admin / \$GRAFANA_ADMIN_PASSWORD, default admin)"
    echo "  Cowrie:     host :22 (SSH), :23 (Telnet)"
    echo "  Dionaea:    host :21, :80, :443, :445, :1433, :3306, :5060, ..."
}

case "$MODE" in
    stop)  do_stop ;;
    reset) do_reset ;;
    up)    do_up ;;
esac