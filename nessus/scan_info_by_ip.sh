#!/bin/bash
#
# scan_info_by_ip.sh
#
# Given an IP address, searches .nessus (XML) files in the current
# directory and lists what scans it was found in and credentialed check info.
#

IP="$1"
if [[ -z "$IP" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <IP>" >&2
    exit 1
fi

for nessus_file in $(grep -rl 'ReportHost name="'"$IP"'"' .); do
    report_name=$(grep 'Report name' "$nessus_file" | cut -d'"' -f2)
    report_section=$(cat "$nessus_file" | sed -n '/<ReportHost name="'"$IP"'"/,/<\/ReportHost/{p;/<\/ReportHost/q}')
    credential_line=$(echo "$report_section" | grep 'Credentialed checks')

    echo "Scan file:   $nessus_file"
    echo "Report name: $report_name"
    echo "$credential_line"
    echo
done
