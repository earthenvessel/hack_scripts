#!/bin/bash
#
# cname_chains.sh
#
# Parse a zdns JSON file and visually show CNAME resolution chains.
#

json_file="$1"
if [[ ! -f "$json_file" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <zdns_output.json>" >&2
    exit 1
fi

# get list of unique base CNAMEs to start from
cnames=( $(cat "$json_file" | jq --raw-output 'select(.results.[].data != {}) | select(.results.[].data.answers) | select(.results.[].data.answers[].type == "CNAME") | .name' | sort -u) )

# loop through base CNAMEs
for cname in "${cnames[@]}"; do

    # set starting color code
    color_code=35 # purple
    echo -en "\e[${color_code}m"

    # print base CNAME and set next line starter
    echo "$cname"
    line_start=' |-> '

    # loop through lines of the dig response
    for line in $(dig "$cname" +short); do

        # if this is another cname...
        if [[ "$line" =~ \.$ ]]; then
            # remove trailing dot
            line=$(echo "$line" | sed 's/\.$//')
            resolution_is_cname=true
        else
            resolution_is_cname=false
        fi

        # Progress color code
        # 35 -> 34 -> 36 -> 32
        case "$color_code" in
            35)
                color_code=34
                ;;
            34)
                color_code=36
                ;;
            36)
                color_code=32
                ;;
        esac
        echo -en "\e[${color_code}m"
        echo "${line_start}${line}"

        if [[ "$resolution_is_cname" == 'true' ]]; then
            line_start="  ${line_start}"
        fi
    done
    echo

    # Reset color
    echo -en "\e[0m"
    line_start=''

done
