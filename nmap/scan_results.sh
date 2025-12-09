#!/bin/bash
#
# scan_results.sh
#
# Nmap scan parsing script. Mode determined by input.
#

#
##
### global variables ###
##
#
VERBOSE=false
declare -A ip_port_services=()

#
##
### define functions ###
##
#

###
# parse_single_gnmap
#
# Given a gnmap file, parse it into the global ip_port_services
# array, ignoring duplicates.
#
parse_single_gnmap() {
    gnmap_file="$1"
    while IFS="" read -r line || [ -n "$line" ]; do
        # if host has at least one open port
        if [[ "$line" =~ /open/ ]]; then
            host_ip=$(echo "$line" | awk '{print $2}')
            # loop through service strings in the line
            while read -r service_string; do
                open_port=$(echo "$service_string" | cut -d/ -f1)
                if [[ -z "${ip_port_services[$host_ip|$open_port]}" ]]; then
                    if [[ "$VERBOSE" == true ]]; then
                        echo "# Adding new ip_port: $host_ip|$open_port: $service_string"
                    fi
                    ip_port_services["$host_ip|$open_port"]="$service_string"
                else
                    if [[ "$VERBOSE" == true ]]; then
                        echo "# ip_port already seen. Skipping: $host_ip|$open_port: $service_string"
                    fi
                fi
            done <<< "$(echo $line | grep -Po '\d+/open/([^/]*/{1,2}){3}')"
        fi
    done < "$gnmap_file"
}

###
# parse_all_gnmap
#
# Parses all gnmap files in the current directory, prioritizing the
# "aggressive" ones.
#
parse_all_gnmap() {
    # parse aggressive gnmap files
    for agg_file in $(ls *aggressive.gnmap 2>/dev/null); do
        parse_single_gnmap "$agg_file"
    done
    # parse non-aggressive gnmap files
    for non_agg_file in $(ls *.gnmap | grep -v aggressive.gnmap); do
        parse_single_gnmap "$non_agg_file"
    done
}

###
# host_output
#
# Show all scan results in Nmap format for a specific host.
#
host_output() {
    TARGET="$1"

    # Pattern explanation:
    # Pull out matches starting with the "scan report" line and either containing the
    # body pattern somewhere and ending with a blank line, or just ending with a "host
    # timeout" error message.
    START_PATTERN="Nmap scan report for ([a-zA-Z0-9.\-]+ \()?$TARGET( |\)|\n)"
    BODY_PATTERN="(PORT|All \d+ scanned ports)"
    END_PATTERN="\n\n"

    GREP_PATTERN="$START_PATTERN(.|\n)+?($BODY_PATTERN(.|\n)+?$END_PATTERN|due to host timeout\n)"

    for nmap_file in $(ls *.nmap); do
        echo "##### $nmap_file #####"
        grep --null-data --perl-regexp --only-matching "$GREP_PATTERN" "$nmap_file"
        echo
    done
}

###
# ports
#
# Looks for unique port numbers from gnmap files and prints list sorted by number of
# IPs matching.
#
ports() {
    parse_all_gnmap

    ports_file='sr_ports_latest.txt'
    echo "# $(date)" > "$ports_file"

    # create array of port counts
    declare -A port_counts=()
    for ip_port in "${!ip_port_services[@]}"; do
        port=$(echo "$ip_port" | cut -d'|' -f2)
        if [[ -z "${port_counts[$port]}" ]]; then
            port_counts["$port"]=1
        else
            port_counts["$port"]=$(("${port_counts[$port]}" + 1))
        fi
    done

    # echo and sort array
    for port in "${!port_counts[@]}"; do
        echo -e "${port_counts[$port]}\t${port}"
    done | sort --numeric-sort --reverse | tee --append "$ports_file"
}

###
# services
#
# Looks for unique service strings from gnmap files and prints list sorted by number of
# IPs matching that service string.
#
services() {
    parse_all_gnmap

    services_file='sr_services_latest.txt'
    echo "# $(date)" > "$services_file"

    # create array of service counts
    declare -A service_counts=()
    for service_string in "${ip_port_services[@]}"; do
        if [[ -z "${service_counts[$service_string]}" ]]; then
            service_counts["$service_string"]=1
        else
            service_counts["$service_string"]=$(("${service_counts[$service_string]}" + 1))
        fi
    done

    # echo and sort array
    for service_string in "${!service_counts[@]}"; do
        echo -e "${service_counts[$service_string]}\t${service_string}"
    done | sort --numeric-sort --reverse | tee --append "$services_file"
}

###
#
# add_urls_to_file_for_port
#
# Support function for web.
# Given an IP/hostname and port, add appropriate URLs to the given file.
#
add_urls_to_file_for_port() {
    host_l="$1"
    port_l="$2"
    outfile_l="$3"

    # if host looks like IPv6, wrap it in square brackets
    if [[ "$host_l" =~ ':' ]]; then
        host_l="[$host_l]"
    fi

    # add http:// URL for all except 443
    if [[ "$port_l" != 443 ]]; then
        # if port is 80...
        if [[ "$port_l" == 80 ]]; then
            # don't add port to URL
            server_l="$host_l"
        else
            # otherwise add the port to the URL
            server_l="${host_l}:${port_l}"
        fi
        echo "http://${server_l}" >> "$outfile_l"
    fi

    # add https:// URL for all except 80
    if [[ "$port_l" != 80 ]]; then
        # if port is 443...
        if [[ "$port_l" == 443 ]]; then
            # don't add port to URL
            server_l="$host_l"
        else
            # otherwise add the port to the URL
            server_l="${host_l}:${port_l}"
        fi
        echo "https://${server_l}" >> "$outfile_l"
    fi
}

###
#
# web
#
# Prepare a list of likely web services for screenshotting
#
web() {
    parse_all_gnmap

    # array to hold host-ports that are likely web services
    web_host_ports=()

    # loop through all ip-port->services
    for ip_port in "${!ip_port_services[@]}"; do
        IP=$(echo "$ip_port" | cut -d'|' -f1)
        port=$(echo "$ip_port" | cut -d'|' -f2)

        hostnames_for_this_ip=()

        # look up forward DNS resolutions for this IP
        while read -r HOSTNAME; do
            # add to array if not there
            if [[ ! " ${hostnames_for_this_ip[*]} " =~ [[:space:]]${HOSTNAME}[[:space:]] ]]; then
                hostnames_for_this_ip+=("${HOSTNAME}")
            fi
        done <<< $(grep -Ph "Nmap scan report for .* \($IP\)" *.nmap | awk '{print $5}' | sort -u)

        # look up reverse DNS resolution for this IP
        while read -r HOSTNAME; do
            # add to array if not there
            if [[ ! " ${hostnames_for_this_ip[*]} " =~ [[:space:]]${HOSTNAME}[[:space:]] ]]; then
                hostnames_for_this_ip+=("${HOSTNAME}")
            fi
        done <<< $(grep -h "rDNS record for ${IP}:" *.nmap | awk '{print $5}' | sort -u)

        # if port ends in 80 or 443, or service string contains 'http'
        if [[ "$port" =~ (80|443)$ || "${ip_port_services[$ip_port]}" =~ http ]]; then
            if [[ "$VERBOSE" == true ]]; then
                echo "# Likely web port: $ip_port"
            fi

            # add IP-port to array if not there
            if [[ ! " ${web_host_ports[*]} " =~ " ${ip_port} " ]]; then
                web_host_ports+=("$ip_port")
            fi

            # add all hostname|ports to array if not there
            for hostname_l in "${hostnames_for_this_ip[@]}"; do
                # as a sanity check, only enter hostnames that aren't blank
                if [[ $(echo "$hostname_l" | grep -Pv '^\s*$') ]]; then
                    if [[ ! " ${web_host_ports[*]} " =~ " ${hostname_l}|${port} " ]]; then
                        web_host_ports+=("${hostname_l}|${port}")
                    fi
                fi
            done
        fi

        unset hostnames_for_this_ip
    done

    # create URL file
    url_filename=web_service_urls_$(date "+%Y-%m-%d_%T").txt
    for web_host_port in "${web_host_ports[@]}"; do
        host_local=$(echo "$web_host_port" | cut -d'|' -f1)
        port=$(echo "$web_host_port" | cut -d'|' -f2)

        add_urls_to_file_for_port "$host_local" "$port" "$url_filename"
    done

    echo "# Potential web URLs saved to file: $url_filename"
}

###
#
# tcp_scanned
#
# Output a list of all TCP ports that have been scanned
#
tcp_scanned() {
    tcp_scanned_ports=()
    # Carve out scaninfo lines from XML files
    for port in $(grep '^<scaninfo' *.xml | grep -Po 'protocol="tcp" numservices="\d+" services="([\d-]+,?)+"' | cut -d'"' -f6 | tr ',' '\n' | sort -u); do
        # Expand ranges and add all to array
        if [[ "$port" =~ '-' ]]; then
            tcp_scanned_ports+=( $(seq ${port/-/ }) )
        else
            tcp_scanned_ports+=("$port")
        fi
    done
    # Deduplicate array and output
    printf "%s\n" "${tcp_scanned_ports[@]}" | sort -uh
}

###
# open_port
#
# Given a port, search through Nmap scan output and report all hosts with that port open
#
open_port() {
    port="$1"
    cat *.gnmap | grep " ${port}/open/" | awk '{print $2}' | sort -u --version-sort
}

#
##
### main logic ###
##
#

if [[ "$1" == 'ports' ]]; then
    ports
elif [[ "$1" == 'services' ]]; then
    services
elif [[ "$1" == 'web' ]]; then
    web
elif [[ "$1" == 'tcp_scanned' ]]; then
    tcp_scanned
elif [[ $(echo "$1" | grep -P '^\d+$') ]]; then           # integer (port num)
    open_port "$1"
elif [[ $(echo "$1" | grep -P '^(\d+\.){3}\d+$') ]]; then # IPv4 address
    host_output "$1"
elif [[ $(echo "$1" | grep -P '.+') ]]; then              # assume hostname
    host_output "$1"
else
    echo 'Usage:' >&2
    echo "    $0 <ports|services|web|tcp_scanned|PORT_NUM|IP|DNS_NAME>" >&2
    exit 1
fi
