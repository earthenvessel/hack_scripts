#!/bin/bash
#
# simple_https_server.sh
#
# Starts an HTTPS server with a temporary auto-generated cert.
# Uses php and ncat.
#

# kill all processes on exit
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# print help if requested
if [[ "$1" == '-h' || "$1" == '--help' ]]; then
    echo 'Usage:' >&2
    echo "    $0 [port] [web_root]" >&2
    echo >&2
    echo 'Defaults to TCP 443 in current directory' >&2
    exit 1
fi

# override default TLS port if specified
TLS_PORT="$1"
if [[ -z "$TLS_PORT" ]]; then
    TLS_PORT=443
fi

# if TLS port is privileged, prompt for sudo password early to
# avoid output stream confusion
if [[ "$TLS_PORT" -lt 1024 ]]; then
    sudo echo > /dev/null
    SUDO_OR_NOT=sudo
fi

# if web root directory was provided, go there
WEB_ROOT="$2"
if [[ ! -z "$WEB_ROOT" ]]; then
    cd "$WEB_ROOT"
fi

# pick high end port for web service
ACTUAL_WEB_PORT=$(shuf -i 49152-65535 -n 1)

# open port forward between TLS port and actual web service
echo Starting TLS forwarder on port "$TLS_PORT"
$SUDO_OR_NOT ncat -k -lnp "$TLS_PORT" --ssl -c "ncat localhost $ACTUAL_WEB_PORT" &

# start web service on high end port
php -S localhost:"$ACTUAL_WEB_PORT"
