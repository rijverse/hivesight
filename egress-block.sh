#!/bin/sh
# Isolate the honeypot network: containers on honeypot-net may answer
# inbound connections and reach the backend network, nothing else.
#
# Rules live in DOCKER-USER, the chain Docker reserves for operator rules.
# Anything put directly in FORWARD gets pushed below Docker's own jumps
# whenever the daemon restarts, silently disabling the block.
#
# Run as root after `docker compose up` (bin/up.sh does this) and again
# after any docker daemon restart.
#
#   egress-block.sh          install the block
#   egress-block.sh --down   remove the rules again (bin/up.sh --stop does this)
#
# Verify: docker exec cowrie wget -qO- --timeout=3 https://example.com  (should fail)

set -e

PROJECT="${COMPOSE_PROJECT_NAME:-hivesight}"

MODE="up"
[ "${1:-}" = "--down" ] && MODE="down"

subnet_of() {
    # Empty string if the network doesn't exist (e.g. no honeypots selected).
    docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$1" 2>/dev/null || true
}

HONEY_SUBNET=$(subnet_of "${PROJECT}_honeypot-net")
BACKEND_SUBNET=$(subnet_of "${PROJECT}_backend")

if [ -z "$HONEY_SUBNET" ]; then
    echo "[i] no ${PROJECT}_honeypot-net network; nothing to isolate"
    exit 0
fi

ensure() {
    iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER 1 "$@"
}

remove() {
    # A rule can exist more than once after repeated installs; clear them all.
    while iptables -C DOCKER-USER "$@" 2>/dev/null; do
        iptables -D DOCKER-USER "$@"
    done
}

apply() {
    op="$1"
    $op -s "$HONEY_SUBNET" -j DROP
    [ -n "$BACKEND_SUBNET" ] && $op -s "$HONEY_SUBNET" -d "$BACKEND_SUBNET" -j ACCEPT
    $op -s "$HONEY_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

if [ "$MODE" = "down" ]; then
    apply remove
    echo "[+] egress block removed for $HONEY_SUBNET"
    exit 0
fi

# Inserted in reverse order so the final chain reads:
#   1. accept replies to inbound connections (attacker traffic must flow back)
#   2. accept honeypot -> backend (log shipping)
#   3. drop everything else the honeypots originate
apply ensure

echo "[+] egress block installed for $HONEY_SUBNET (backend ${BACKEND_SUBNET:-none} allowed)"
iptables -L DOCKER-USER -n -v | grep -E "Chain|$HONEY_SUBNET" || true
