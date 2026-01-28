#!/bin/bash
#
# bulk_resolve_dns.sh
#
# Takes a list of DNS names and runs them through zdns [with
# the specified query type] to attempt to resolve them. Creates
# a list of resolvable ones (any answer counts, including a 
# dangling CNAME).
#

# args
dns_names_file="$1"
query_type="$2"
if [[ ! -r "$dns_names_file" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <dns_names_file>.txt [query_type]" >&2
    exit 1
fi
if [[ -z "$query_type" ]]; then
    query_type='A'
fi

# confirm zdns in PATH
if [[ -z $(which zdns) ]]; then
    echo 'zdns not found in PATH' >&2
    exit 2
fi

# create output filenames
base_output_file="$(basename $dns_names_file | sed 's/\.txt//' | sed 's/_potential_subs//')"_$query_type
zdns_output_file="$base_output_file.json"

# build zdns flags
zdns_flags=("$query_type")
zdns_flags+=('--name-servers' '1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.10,149.112.112.10')
zdns_flags+=('--result-verbosity' 'short')
zdns_flags+=('--verbosity' '2')
zdns_flags+=('--threads' '100') # default 1,000
zdns_flags+=('--retries' '2')   # default 1
zdns_flags+=('--output-file' "$zdns_output_file")

# resolve DNS names
cat "$dns_names_file" | zdns "${zdns_flags[@]}"
echo "zdns output saved to:           $zdns_output_file"

# extract resolvable names from zdns file
resolvable_file="${base_output_file}_resolvable.txt"
jq --raw-output 'select(.results.'"$query_type"'.data.answers) | .name' "$zdns_output_file" | sort -u > "$resolvable_file"
echo "Resolvable DNS names saved to:  $resolvable_file"
