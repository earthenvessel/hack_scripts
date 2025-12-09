#!/usr/bin/env python3
#
# port_enum.py
#
# Wrapper around Nmap for easy typical use
#

import os
import sys
import subprocess
import xml.etree.ElementTree as ET

# handle args
if len(sys.argv) < 2:
    print('Usage:')
    print(f"{sys.argv[0]} [--dry-run] <TARGET> [nmap_flag_passthrough]", file=sys.stderr)
    sys.exit(1)

# check first for arguments specific to this script
dry_run = False
if '--dry-run' in sys.argv:
    dry_run = True
    sys.argv.remove('--dry-run')

# parse remaining arguments
target = sys.argv[1]

additional_nmap_flags = sys.argv[2:]
base_nmap_args = ['-T4', '--host-timeout', '30m', '--resolve-all'] + additional_nmap_flags

# set variables
output_dir = "nmap"
exclusion_file = 'exclusions.txt'

# create target friendly name
target_friendly_name = os.path.basename(target).replace('.txt', '').replace('.', '-')

# check if target is a file
if os.path.isfile(target):
    base_nmap_args += ['-iL', target]
else: # assume target is a domain name or IP
    base_nmap_args.append(target)

# set output filenames
output_base_name = f"{output_dir}/{target_friendly_name}"
quick_scan_file = f"{output_base_name}_top_1000"
full_scan_file = f"{output_base_name}_full_tcp"
agg_scan_file = f"{output_base_name}_aggressive"
udp_scan_file = f"{output_base_name}_udp_500"

# check for exclusions file
if os.path.isfile(exclusion_file):
    base_nmap_args += ['--excludefile', exclusion_file]

# make output directory if needed
if not os.path.isdir(output_dir):
    os.mkdir(output_dir)

#
##
### main scans ###
##
#

# initial scan for quick results
print('Quick scan of top 1,000 ports...')
quick_scan_cmd = ['sudo', 'nmap'] + base_nmap_args + ['-oA', quick_scan_file]
if dry_run:
    print(' '.join(quick_scan_cmd))
else:
    subprocess.run(quick_scan_cmd)
print()

# full TCP scan
print('Full TCP scan...')
full_scan_cmd = ['sudo', 'nmap'] + base_nmap_args + ['-p-', '-oA', full_scan_file]
if dry_run:
    print(' '.join(full_scan_cmd))
else:
    subprocess.run(full_scan_cmd)
print()

# Parse .xml files to get open ports
print('Parsing XML files for open ports...')
open_ports = []
for file_name in os.listdir(output_dir):
    if file_name.endswith('.xml'):
        try:
            tree = ET.parse(os.path.join(output_dir, file_name))
            root = tree.getroot()
        except ET.ParseError:
            print(f"WARNING: Unable to parse file: {file_name}", file=sys.stderr)
        for port in root.findall(".//port"):
            for child in port:
                if child.tag == 'state':
                    port_int = int(port.get('portid'))
                    if child.attrib['state'] == 'open' and port_int not in open_ports:
                        open_ports.append(port_int)

# manually add 61992 so we have a likely closed port
open_ports.append(61992)

# Construct port_list
open_ports.sort()
port_list = ','.join(str(p) for p in open_ports)
print()

# aggressive scan, only on ports seen open
print('Service, script, and OS scan on open TCP ports...')
agg_scan_args = base_nmap_args + ['-p', port_list, '-sV', '--version-all', '-sC', '-O', '-oA', agg_scan_file]
agg_scan_cmd = ['sudo', 'nmap'] + agg_scan_args
if dry_run:
    print(' '.join(agg_scan_cmd))
else:
    subprocess.run(agg_scan_cmd)
print()

# UDP scan
print('UDP scan on top 500 ports...')
udp_scan_cmd = ['sudo', 'nmap'] + base_nmap_args + ['-sU', '--top-ports', '500', '-oA', udp_scan_file]
if dry_run:
    print(' '.join(udp_scan_cmd))
else:
    subprocess.run(udp_scan_cmd)

# change ownership of output files
user_uid = int(os.environ.get('SUDO_UID', os.geteuid()))
user_gid = int(os.environ.get('SUDO_GID', os.getegid()))
for root_dir, sub_dirs, files in os.walk(output_dir):
    os.chown(root_dir, user_uid, user_gid)
    for file_name in files:
        file_path = os.path.join(root_dir, file_name)
        os.chown(file_path, user_uid, user_gid)
