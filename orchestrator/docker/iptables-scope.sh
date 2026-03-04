#!/bin/bash
# Scope enforcement via iptables inside container network namespace
# Usage: iptables-scope.sh <allowed_cidr1> [allowed_cidr2] ...

set -euo pipefail

# Flush existing rules
iptables -F OUTPUT

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS (needed for resolution)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specified CIDRs
for cidr in "$@"; do
    iptables -A OUTPUT -d "$cidr" -j ACCEPT
done

# Drop everything else
iptables -A OUTPUT -j DROP

echo "Scope enforced: allowed CIDRs: $*"
