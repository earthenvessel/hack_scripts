#!/bin/bash
#
# null_session_check.sh
#
# Bulk check for SMB/RPC null or guest sessions using multiple methods.
#

# check args and set variables
TARGET_FILE="$1"
TIMEOUT="$2"
if [[ ! -r "$TARGET_FILE" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <TARGET_FILE> [TIMEOUT]" >&2
    exit 1
fi

if [[ -z "$TIMEOUT" ]]; then
    TIMEOUT=10
fi

OUTPUT_FILE=null_check_$(date "+%Y-%m-%d_%T").txt

# define functions
cmd_wrapper () {
    CMD="$1"
    echo "### $CMD ###" | tee --append "$OUTPUT_FILE"
    for IP in $(cat "$TARGET_FILE"); do
        echo "# $IP #"
        timeout "$TIMEOUT" $CMD "$IP"
    done | tee --append "$OUTPUT_FILE"
}

smbmap_wrapper () {
    AUTH_STRING="$1"
    CMD="smbmap --no-banner --host-file $TARGET_FILE"
    if [[ -n "$AUTH_STRING" ]]; then
        CMD+=" $AUTH_STRING"
    fi
    echo "### $CMD ###" | tee --append "$OUTPUT_FILE"
    timeout "$TIMEOUT" $CMD | tee --append "$OUTPUT_FILE"
}

# rpcclient
echo '##### rpcclient #####' | tee --append "$OUTPUT_FILE"
cmd_wrapper 'rpcclient --command=srvinfo --user="" --no-pass'
cmd_wrapper 'rpcclient --command=srvinfo --user="" --password=""'
cmd_wrapper 'rpcclient --command=srvinfo --user=% --no-pass'
cmd_wrapper 'rpcclient --command=srvinfo --user=% --password=""'

# smbclient
echo '##### smbclient #####' | tee --append "$OUTPUT_FILE"
cmd_wrapper 'smbclient --user="" --no-pass -L'
cmd_wrapper 'smbclient --user="" --password="" -L'
cmd_wrapper 'smbclient --user=% --no-pass -L'
cmd_wrapper 'smbclient --user=% --password="" -L'

# check smbmap anonymous
echo '##### smbmap null #####' | tee --append "$OUTPUT_FILE"
smbmap_wrapper

# check smbmap guest
echo '##### smbmap guest #####' | tee --append "$OUTPUT_FILE"
smbmap_wrapper '-u testuser'

# check enum4linux
echo '##### enum4linux #####' | tee --append "$OUTPUT_FILE"
cmd_wrapper 'enum4linux'
