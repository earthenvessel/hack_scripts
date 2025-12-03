#!/bin/bash
#
# curler.sh
#
# Curl a URL and look for a regex pattern.
#

set -o errexit

# validate args
url_file="$1"
path="$2"
search_regex="$3"
if [[ ! -r "$url_file" || ! -n "$path" || ! -n "$search_regex" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <base_url_file> <path> <search_regex>" >&2
    exit 1
fi

# set constants
readonly TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
readonly OUTPUT_DIR="curler_$TIMESTAMP"
readonly LOGFILE="$OUTPUT_DIR/curler.log"

# define curl error code lookups
code_lookup[7]='Connection refused'
code_lookup[28]='TIMEOUT'
code_lookup[35]='SSL_ERROR'
code_lookup[52]='Empty reply'
code_lookup[56]='RECV FAIL'

# functions
print_and_log() {
    local message="$1"
    echo "$message" | tee --append "$LOGFILE"
}

# create subdirectory for page contents
mkdir "$OUTPUT_DIR"

# main loop through url file
cat "$url_file" | while read base_url; do

    # assemble target url, removing any trailing slash from base and leading
    # slash from path
    target_url="${base_url/%\//}/${path/#\//}"

    # curl and check exit code for errors
    output_file="$OUTPUT_DIR/${target_url//\//_}.out"
    exit_code=0
    curl --silent --insecure --connect-timeout 3 --max-timeout 10 "$target_url" -o "$output_file" || exit_code=$?
    if [[ "$exit_code" -ne 0 ]]; then
        if [[ -n "${code_lookup[$exit_code]}" ]]; then
            print_and_log "${code_lookup[$exit_code]},$target_url"
        else
            print_and_log "???,$target_url"
        fi
        continue
    fi

    # check output file for regex pattern
    if [[ -n $(grep -P "$search_regex" "$output_file") ]]; then 
        print_and_log "YES,$target_url"
    else
        print_and_log "NO,$target_url"
        rm "$output_file"
    fi

done
