#!/bin/sh
# Apply before first PHP bootstrap, only to the newly allocated internal bridge.
# Containers have no automatic restart policy; recheck this boundary before any restart.
set -eu
test "$(id -u)" = 0
project=${1:?Compose project required}
case "$project" in ''|*[!a-z0-9_-]*) exit 2 ;; esac
network="${project}_closed"
test "$(docker network inspect -f '{{.Internal}}' "$network")" = true
test "$(docker network inspect -f '{{.Driver}}' "$network")" = bridge
test "$(docker network inspect -f '{{.EnableIPv6}}' "$network")" = false
id=$(docker network inspect -f '{{.Id}}' "$network")
test "${#id}" = 64
case "$id" in *[!a-f0-9]*) exit 2 ;; esac
bridge="br-$(printf '%s' "$id" | cut -c1-12)"
ip link show dev "$bridge" >/dev/null
subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$network")
case "$subnet" in 10.234.*.0/24) ;; *) printf 'Unexpected stage subnet\n' >&2; exit 1 ;; esac
chain=SUHOPUT2-STAGE
for tool in iptables ip6tables; do
    if "$tool" -w -S "$chain" >/dev/null 2>&1; then
        expected=$(printf '%s\n' "-N $chain" "-A $chain -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN" "-A $chain -j DROP")
        test "$("$tool" -w -S "$chain")" = "$expected"
        "$tool" -w -C INPUT -i "$bridge" -j "$chain"
    else
        "$tool" -w -N "$chain"
        "$tool" -w -A "$chain" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
        "$tool" -w -A "$chain" -j DROP
        "$tool" -w -I INPUT 1 -i "$bridge" -j "$chain"
    fi
    first=$("$tool" -w -S INPUT | awk '/^-A INPUT / { print; exit }')
    test "$first" = "-A INPUT -i $bridge -j $chain"
done
printf 'PASS: host INPUT blocked only for %s (%s)\n' "$bridge" "$subnet"
