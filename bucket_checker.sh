#!/bin/bash
#
# bucket_checker.sh
#
# Take a list of S3 buckets (optionally with "directories" appended) 
# and check for public permissions.
#

# Handle args
bucket_dir_file="$1"
if [[ ! -r "$bucket_dir_file" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <file_of_bucket_directories>" >&2
    echo >&2
    echo "Example file:" >&2
    echo "    wrapper3000" >&2
    echo "    mybucket" >&2
    echo "    mybucket/mydir" >&2
    echo "    ..." >&2
    exit 1
fi

# Functions
function output {
    message="$1"
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e '[+] '"$timestamp $message"
}

function cmd_wrapper {
    cmd="$1"
    #cmd_output=$($cmd 2>&1)
    cmd_output=$("$@" 2>&1)
    if [[ "$cmd_output" =~ 'AccessDenied' ]]; then
        output '    \e[31mAccess Denied\e[0m'
    elif [[ "$cmd_output" =~ 'NoSuchBucket' ]]; then
        output '    \e[31mNoSuchBucket\e[0m'
    elif [[ "$cmd_output" =~ 'does not exist' ]]; then
        output '    \e[31mDoes not exist\e[0m'
    else
        output '    \e[32mSuccess!\e[0m'
    fi
}

# Global variables
checked_buckets=()

# Create a temp file to test write access
UUID=$(uuidgen)
filename="${UUID}.txt"
temp_file="/tmp/${filename}"
output "Creating temp file: $temp_file"
echo 'Hello' > "$temp_file"

# Main loop through file contents
while IFS= read -r line; do
    # Strip any trailing slashes
    bucket_dir="$(echo $line | sed -r 's/\/+$//')"

    # Get bucket name if this line contains a directory
    if [[ "$bucket_dir" =~ '/' ]]; then
        bucket_name="$(echo $bucket_dir | cut -d/ -f1)"
    else
        bucket_name="$bucket_dir"
    fi

    url="s3://${bucket_dir}"
    output "\e[34mChecking $url\e[0m"

    output '  Attempting to list objects...'
    cmd_array=('aws' 's3' 'ls' '--no-sign-request' "${url}/")
    cmd_wrapper "${cmd_array[@]}"

    output '  Attempting to upload object...'
    cmd_array=('aws' 's3' 'cp' '--no-sign-request' "$temp_file" "${url}/${filename}")
    cmd_wrapper "${cmd_array[@]}"

    # Confirm we haven't already tried checking bucket ACL
    if [[ " ${checked_buckets[*]} " =~ " $bucket_name " ]]; then
        output '  Already tried checking bucket ACL. Skipping.'
    else
        output '  Attempting to read bucket ACL...'
        cmd_array=('aws' 's3api' 'get-bucket-acl' '--no-sign-request' '--bucket' "$bucket_name")
        cmd_wrapper "${cmd_array[@]}"
        checked_buckets+=("$bucket_name")
    fi
done < "$bucket_dir_file"
