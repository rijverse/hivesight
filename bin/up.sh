#!/usr/bin/env bash
# bin/up.sh — launcher for the honeypot stack.
#
# The stack is split into four bundles you can mix and match:
#   cowrie    SSH/Telnet honeypot
#   dionaea   multi-protocol honeypot (FTP/HTTP/SMB/MySQL/Redis/Mongo/...)
#   logging   Loki + Promtail + Grafana dashboards
#   ai        local-LLM triage + ClamAV malware scanning
#
# Usage:
#   bin/up.sh                     # pick bundles interactively, then start
#   bin/up.sh --all               # start every bundle
#   bin/up.sh --cowrie --logging  # start only the named bundles
#   bin/up.sh --stop              # stop and remove containers
#   bin/up.sh --reset             # stop + delete named volumes (DESTROYS data)
#   bin/up.sh --pull [bundles]    # pull images before starting
#
# Copy .env.example to .env to change ports or the Grafana password.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load .env so the port values below match what compose will actually bind.
if [[ -f .env ]]; then
    set -a
    # optional runtime file, not present at lint time
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

# Compile the friendly EXCLUDE_IPS list into the anchored regex the promtail
# drop stage needs, unless the user pinned EXCLUDE_IP_REGEX directly. Dots are
# escaped and the whole thing anchored so a short IP can't match a longer one.
# Exported so compose interpolation (promtail, orchestrator) picks it up.
if [[ -z "${EXCLUDE_IP_REGEX:-}" && -n "${EXCLUDE_IPS:-}" ]]; then
    IFS=', ' read -ra _ips <<< "$EXCLUDE_IPS"
    _alt=""
    for _ip in "${_ips[@]}"; do
        [[ -z "$_ip" ]] && continue
        _alt="${_alt:+$_alt|}${_ip//./\\.}"
    done
    [[ -n "$_alt" ]] && export EXCLUDE_IP_REGEX="^($_alt)\$"
fi

ALL_BUNDLES=(cowrie dionaea logging ai)

MODE="up"
PULL=0
WANT=()

for arg in "$@"; do
    case "$arg" in
        --stop) MODE="stop" ;;
        --reset) MODE="reset" ;;
        --pull) PULL=1 ;;
        --all) WANT=("${ALL_BUNDLES[@]}") ;;
        --cowrie|--dionaea|--logging|--ai) WANT+=("${arg#--}") ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose-ai-av.yml)

has() { local x; for x in ${WANT[@]+"${WANT[@]}"}; do [[ "$x" == "$1" ]] && return 0; done; return 1; }

# Host ports each bundle publishes, for the collision check.
bundle_ports() {
    case "$1" in
        cowrie)  echo "${COWRIE_SSH_PORT:-22} ${COWRIE_TELNET_PORT:-23}" ;;
        dionaea) echo "21 80 443 445 3306 1433 1883 5060 5061 6379 8081 11211 27017" ;;
        logging) echo "3000" ;;
        *)       echo "" ;;
    esac
}

choose_bundles() {
    echo "Which bundles do you want to run? [Y/n each, blank = yes]" >&2
    local b ans desc
    for b in "${ALL_BUNDLES[@]}"; do
        case "$b" in
            cowrie)  desc="SSH/Telnet honeypot" ;;
            dionaea) desc="multi-protocol honeypot (FTP/HTTP/SMB/MySQL/...)" ;;
            logging) desc="Loki + Promtail + Grafana dashboards" ;;
            ai)      desc="local-LLM triage + ClamAV scanning (~4 GB RAM)" ;;
        esac
        printf '  %-9s %s ' "$b" "$desc" >&2
        read -r ans || ans=""
        [[ "$ans" =~ ^[Nn] ]] || WANT+=("$b")
    done
}

preflight() {
    command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
    docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 1; }
    docker compose version >/dev/null 2>&1 || { echo "docker compose plugin not found" >&2; exit 1; }

    has ai && mkdir -p orchestrator-data
    if has logging; then
        mkdir -p grafana-provisioning/dashboards/files
        cp -f dashboards/*.json grafana-provisioning/dashboards/files/
    fi

    # Only warn about collisions on a fresh start; on a re-run the ports are
    # held by our own containers, which isn't a conflict.
    local running b p
    running=$("${COMPOSE[@]}" ps -q 2>/dev/null | head -1 || true)
    [[ -n "$running" ]] && return 0
    for b in "${WANT[@]}"; do
        for p in $(bundle_ports "$b"); do
            if ss -ltn "sport = :$p" 2>/dev/null | tail -n +2 | grep -q LISTEN; then
                echo "warning: host port $p (needed by '$b') is already in use" >&2
                [[ "$b" == cowrie ]] && \
                    echo "         set COWRIE_SSH_PORT / COWRIE_TELNET_PORT in .env to remap cowrie" >&2
            fi
        done
    done
}

profile_args() {
    local b out=()
    for b in "${WANT[@]}"; do out+=(--profile "$b"); done
    printf '%s\n' "${out[@]}"
}

do_up() {
    if [[ ${#WANT[@]} -eq 0 ]]; then
        if [[ -t 0 ]]; then
            choose_bundles
        else
            echo "no bundles given, starting all (use --cowrie/--dionaea/--logging/--ai to pick)" >&2
            WANT=("${ALL_BUNDLES[@]}")
        fi
    fi
    # de-dupe (e.g. --all --cowrie); tolerate an empty selection under set -u
    mapfile -t WANT < <(printf '%s\n' ${WANT[@]+"${WANT[@]}"} | awk 'NF && !seen[$0]++')
    [[ ${#WANT[@]} -eq 0 ]] && { echo "nothing selected" >&2; exit 1; }

    local PROFILES; mapfile -t PROFILES < <(profile_args)

    preflight
    if (( PULL )); then
        "${COMPOSE[@]}" "${PROFILES[@]}" pull --ignore-pull-failures || true
    fi
    "${COMPOSE[@]}" "${PROFILES[@]}" up -d

    if has cowrie || has dionaea; then
        echo "installing egress block..."
        if ! sh "$ROOT/egress-block.sh"; then
            echo "warning: egress block failed (not root?); honeypots can reach the internet" >&2
        fi
    fi

    if has logging; then
        echo "waiting for grafana health..."
        for _ in {1..40}; do
            status=$(docker inspect --format='{{.State.Health.Status}}' grafana 2>/dev/null || echo starting)
            [[ "$status" == "healthy" ]] && break
            sleep 2
        done
    fi

    echo "done. running: ${WANT[*]}"
    has logging && echo "  Grafana:  http://localhost:3000  (admin / \${GRAFANA_ADMIN_PASSWORD:-admin})"
    has cowrie  && echo "  Cowrie:   host :${COWRIE_SSH_PORT:-22} (SSH), :${COWRIE_TELNET_PORT:-23} (Telnet)"
    has dionaea && echo "  Dionaea:  host :21 :80 :443 :445 :1433 :3306 :6379 :27017 (and more)"
    has ai      && echo "  AI/AV:    ollama + clamav + orchestrator (no host ports)"
}

# stop/reset act on the whole project regardless of what's selected.
all_profile_args() {
    local b out=()
    for b in "${ALL_BUNDLES[@]}"; do out+=(--profile "$b"); done
    printf '%s\n' "${out[@]}"
}

do_stop() {
    sh "$ROOT/egress-block.sh" --down 2>/dev/null || true
    local P; mapfile -t P < <(all_profile_args)
    "${COMPOSE[@]}" "${P[@]}" down --remove-orphans
}

do_reset() {
    sh "$ROOT/egress-block.sh" --down 2>/dev/null || true
    local P; mapfile -t P < <(all_profile_args)
    "${COMPOSE[@]}" "${P[@]}" down -v --remove-orphans
    echo "all hivesight named volumes deleted"
}

case "$MODE" in
    stop)  do_stop ;;
    reset) do_reset ;;
    up)    do_up ;;
esac
