#!/bin/bash
#
# affected_by_plugin_id.sh
#
# Searches .nessus (XML) files in the current directory and
# lists out all hosts that are affected by the given Plugin ID.
#

plugin_id="$1"
if [[ -z "$plugin_id" ]]; then
    echo 'Usage:' >&2
    echo "    $0 <plugin_id>" >&2                                                                                                                                                                             
    exit 1                                                                                                                                                                                                    
fi                                                                                                                                                                                                            
                                                                                                                                                                                                              
for nessus_file in $(grep -rl 'pluginID="'"$plugin_id"'"' .); do                                                                                                                                              
    for report_host in $(grep '<ReportHost' "$nessus_file" | cut -d'"' -f2); do                                                                                                                               
        report_section=$(cat "$nessus_file" | sed -n '/<ReportHost name="'"$report_host"'"/,/<\/ReportHost/{p;/<\/ReportHost/q}')                                                                             
        if [[ $(echo "$report_section" | grep 'pluginID="'"$plugin_id"'"') ]]; then                                                                                                                           
            echo "$report_host"                                                                                                                                                                               
        fi                                                                                                                                                                                                    
    done                                                                                                                                                                                                      
done | sort -u
