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
# Verify: docker exec cowrie wget -qO- --timeout=3 https://example.com  (should fail)

set -e

PROJECT="${COMPOSE_PROJECT_NAME:-hivesight}"

subnet_of() {
    docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$1"
}

HONEY_SUBNET=$(subnet_of "${PROJECT}_honeypot-net")
BACKEND_SUBNET=$(subnet_of "${PROJECT}_backend")

ensure() {
    iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER 1 "$@"
}

# Inserted in reverse order so the final chain reads:
#   1. accept replies to inbound connections (attacker traffic must flow back)
#   2. accept honeypot -> backend (log shipping)
#   3. drop everything else the honeypots originate
ensure -s "$HONEY_SUBNET" -j DROP
ensure -s "$HONEY_SUBNET" -d "$BACKEND_SUBNET" -j ACCEPT
ensure -s "$HONEY_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] egress block installed for $HONEY_SUBNET (backend $BACKEND_SUBNET allowed)"
iptables -L DOCKER-USER -n -v | grep -E "Chain|$HONEY_SUBNET" || true
