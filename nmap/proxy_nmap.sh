#!/bin/bash
#
# proxy_nmap.sh
#
# Simple wrapper around Nmap for when scanning through a proxy
# with proxychains.
#

nmap_args="$1"
if [[ -z "$nmap_args" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <nmap_args>" >&2
    echo >&2
    echo 'Example:' >&2
    echo "    $0 10.20.30.40 -p22,80" >&2
    exit 1
fi

sudo proxychains -q nmap --unprivileged -T4 -Pn -sT -n "$@"
