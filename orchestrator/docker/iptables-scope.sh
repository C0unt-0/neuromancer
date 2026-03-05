#!/bin/bash
# Scope enforcement via iptables inside container network namespace
# Usage: iptables-scope.sh <allowed_cidr1> [allowed_cidr2] ...

set -euo pipefail

# Safety: only run inside a container
if [ ! -f /.dockerenv ] && ! grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo "Error: This script must only be run inside a Docker container" >&2
    exit 1
fi

# Require at least one CIDR argument
if [ $# -eq 0 ]; then
    echo "Error: No CIDRs specified. Usage: iptables-scope.sh <cidr1> [cidr2] ..." >&2
    exit 1
fi

# Flush existing rules
iptables -F OUTPUT

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS only to system resolvers (prevent DNS tunneling)
while IFS= read -r line; do
    resolver=$(echo "$line" | awk '/^nameserver/ {print $2}')
    if [ -n "$resolver" ]; then
        iptables -A OUTPUT -p udp --dport 53 -d "$resolver" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$resolver" -j ACCEPT
    fi
done < /etc/resolv.conf

# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specified CIDRs
for cidr in "$@"; do
    iptables -A OUTPUT -d "$cidr" -j ACCEPT
done

# Drop everything else
iptables -A OUTPUT -j DROP

echo "Scope enforced: allowed CIDRs: $*"
