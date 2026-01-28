#!/bin/bash
#
# mssql_query.sh
#
# Wrapper around Impacket's mssqlclient to simplify running non-interactive queries.
#

# Update these first
USER='MyDomain/asmith'
PASSWORD='Password1'
TARGET_HOST='10.10.10.10'

# args
query="$1"
if [[ -z "$query" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <query>" >&2
    exit 1
fi

# main
echo "$query" > sql_command.txt
impacket-mssqlclient -windows-auth "$USER":"$PASSWORD"@"$TARGET_HOST" -file sql_command.txt 2>&1 | grep -av 'Impacket v0' | grep -aPv '^\s*$' | grep -av '[*]' | grep -av '^SQL>'
