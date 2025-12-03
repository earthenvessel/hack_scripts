#!/bin/bash
#
# sub_enum.sh
#
# Given a domain, create a list of potential subdomains.
# Uses crt.sh, waybackurls, OWASP amass, and wordlist bruteforce.
#

# Define constants
potential_subs_addon='_potential_subs.txt'
crt_sh_file_addon='_crt_sh.html'
wayback_file_addon='_waybackurls.txt'
amass_file_addon='_amass.txt'
wordlist_directory="${HOME}/.evscripts"
default_wordlist_file="$wordlist_directory/best-dns-wordlist.txt"
default_wordlist_url='https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt'
bruteforce_count=5000
temp_dir='/tmp/sub_enum'

# functions
function print_help_and_exit {
    echo 'Usage:' >&2
    echo "    $0 <domains_file> [wordlist]" >&2
    exit 1
}

function output {
    message="$1"
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo '[+] '"$timestamp $message"
}
                                                                                                                                                                                                             
# Check args                                                                                                                                                                                                 
domains_file="$1"                                                                                                                                                                                            
if [[ ! -r "$domains_file" ]]; then                                                                                                                                                                          
    print_help_and_exit                                                                                                                                                                                      
fi                                                                                                                                                                                                           
                                                                                                                                                                                                             
wordlist="$2"                                                                                                                                                                                                
# if wordlist specified                                                                                                                                                                                      
if [[ -n "$wordlist" ]]; then                                                                                                                                                                                
    # but wordlist not readable                                                                                                                                                                              
    if [[ ! -r "$wordlist" ]]; then                                                                                                                                                                          
        print_help_and_exit                                                                                                                                                                                  
    fi                                                                                                                                                                                                       
# no wordlist specified                                                                                                                                                                                      
else
    # use the default wordlist
    output 'Using default wordlist'
    wordlist="$default_wordlist_file"

    # if default wordlist is not downloaded
    if [[ ! -r "$default_wordlist_file" ]]; then
        output "Default wordlist not found. Downloading to $default_wordlist_file"
        # make sure directory exists
        mkdir "$wordlist_directory" 2>/dev/null
        # download it
        curl -s "$default_wordlist_url" -o "$default_wordlist_file"
    fi
fi

# create temp dir
mkdir "$temp_dir" 2>/dev/null

# check for required tools in PATH
for tool in amass waybackurls; do
    if [[ -z $(which "$tool") ]]; then
        echo "[!] $tool not found in PATH" >&2
        exit 2
    fi
done

# Begin main loop through domains
sort -u "$domains_file" | while read domain; do
    output "Enumerating $domain"
    potential_subs_file="${domain}${potential_subs_addon}"

    # try not to clobber output file
    if [[ -f "$potential_subs_file" ]]; then
        printf "[!] Output file $potential_subs_file already exists. Overwrite? (Y/n) "
        read choice
        if [[ "$choice" == 'n' || "$choice" == 'N' ]]; then
            echo '[!] Exiting'
            exit 3
        fi
    fi

    # crt.sh
    output '  - crt.sh'
    crt_file="${temp_dir}/${domain}${crt_sh_file_addon}"
    curl -s "https://crt.sh/?q=$domain" -o "${crt_file}"
    grep '<TD>' "$crt_file" | grep -Po "[^>]+$domain" | sort -u >> "$potential_subs_file"

    # waybackurls
    output '  - waybackurls'
    wayback_file="${temp_dir}/${domain}${wayback_file_addon}"
    echo "$domain" | waybackurls > "$wayback_file"
    grep -Po "^.+?$domain" "$wayback_file" | sed -r 's/^http.?:\/\///' | sort -u >> "$potential_subs_file"

    # run amass
    output '  - amass'
    amass_file="${temp_dir}/${domain}${amass_file_addon}"
    amass enum -silent -passive -timeout 2 -d "$domain" -o "$amass_file"
    grep -Po "[^\s]+$domain" "$amass_file" >> "$potential_subs_file"
    
    # cycle through wordlist, append potential subs to file
    output '  - Adding subs from wordlist'
    for sub in $(head -"$bruteforce_count" "$wordlist"); do
        echo "${sub}.${domain}" >> "$potential_subs_file"
    done
    
    ### Clean up potential subs file
    output '  - Cleaning up potential subs file'
    # add root domain to file as well for further resolution tools
    echo "$domain" >> "$potential_subs_file"
    # Remove asterisks
    sed -i 's/^*\.//' "$potential_subs_file"
    # Determine longest and shortest subdomains (by number of parts)
    no_dots=$(sed 's/\./ /g' "$potential_subs_file")
    word_counts=$(echo "$no_dots" | while read line; do echo "$line" | wc -w; done | sort -u)
    shortest_entry=$(echo "$word_counts" | head -1)
    longest_entry=$(echo "$word_counts" | tail -1)
    # Confirm every level of child subdomain has its own entry
    for i in $(seq $(("$longest_entry" - "$shortest_entry")) ); do
        grep -Po '([^\.]+\.){'"$i"'}'"$domain" "$potential_subs_file" >> "$temp_dir/$potential_subs_file"
    done
    cat "$temp_dir/$potential_subs_file" >> "$potential_subs_file"

    # Convert all to lowercase, deduplicate, and remove blank lines
    cat "$potential_subs_file" | tr '[:upper:]' '[:lower:]' | grep -Pv '^\s*$' | sort -u -o "$potential_subs_file"

    output "Domain complete: $potential_subs_file"
done

output "Raw tool outputs stored in: $temp_dir/"
