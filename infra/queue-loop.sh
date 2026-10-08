#!/bin/sh
set -eu
# Local isolated runtime only. Every minute is driven by the OS, independent of traffic.
while :; do
    sleep "$((60 - $(date +%s) % 60))"
    if ! timeout 55 wp suhoput queue tick; then
        printf '%s\n' 'Suhoput local queue failed; retry next minute.' >&2
    fi
done
