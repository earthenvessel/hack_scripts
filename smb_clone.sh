#!/bin/bash
#
# smb_clone.sh
#
# Simple utility for cloning a remote SMB share.
#

# Parse args
ip="$1"
user="$2"
pass="$3"
share="$4"
if [[ -z "$share" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <IP> <user> <pass> <share_name>" >&2
    exit 1
fi

# Check if local dir already exists
if [[ -d "$share" ]]; then
    echo -n "'$share' dir already exists. Continue? [Y/n] "
    read response
    if [[ "$response" == n || "$response" == N ]]; then
        exit 1
    fi
else
    mkdir "$share"
fi

# Enter directory and recursively download
cd "$share"
smbclient -c 'mask ""; recurse on; prompt off; mget *' -U "$user" --password="$pass" //"$ip"/"$share"

# List out all the files that were downloaded
echo
find . -type f -exec ls -lh {} +
