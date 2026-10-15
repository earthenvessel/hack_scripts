!/usr/bin/env python3
"""Find a host in Nessus XML scan targets and ReportHost results.

Usage:
    python3 scan_info_by_host.py <IP-or-hostname> [-d DIRECTORY] [-f]

Uses only the Python standard library. Does not perform DNS lookups.
"""

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


HOST_TAGS = {"host-ip", "host-fqdn", "host-rdns", "hostname", "netbios-name"}
CRED_PATTERN = re.compile(r"^\s*Credentialed checks\s*:\s*(.*?)\s*$", re.IGNORECASE)
BRACKETED_IP = re.compile(r"^(.+?)\[([^\[\]]+)\]$")


def local_name(tag):
    """Remove an optional XML namespace from a tag."""
    return tag.rsplit("}", 1)[-1]


def parse_ip(value):
    """Return an IP address, ignoring IPv6 scope IDs when correlating."""
    try:                                                                                                                                                                                                     
        return ipaddress.ip_address(value.strip().split("%", 1)[0])                                                                                                                                          
    except ValueError:                                                                                                                                                                                       
        return None                                                                                                                                                                                          
                                                                                                                                                                                                             
                                                                                                                                                                                                             
def normalize(value):                                                                                                                                                                                        
    """Normalize one IP address or hostname for case-insensitive exact matching."""                                                                                                                          
    value = value.strip().strip("\"'").strip()                                                                                                                                                               
    if value.startswith("[") and value.endswith("]"):                                                                                                                                                        
        value = value[1:-1]                                                                                                                                                                                  
    ip = parse_ip(value)                                                                                                                                                                                     
    return str(ip) if ip is not None else value.rstrip(".").casefold()                                                                                                                                       
                                                                                                                                                                                                             
                                                                                                                                                                                                             
def child_text(element, child_name):
    """Return direct child text, whether or not XML uses a namespace."""
    for child in element:
        if local_name(child.tag) == child_name:
            return child.text or ""
    return ""


def split_targets(value):
    """Tenable uses commas and/or newlines between configured targets."""
    return [item.strip() for item in re.split(r"[,\r\n]+", value or "") if item.strip()]


@dataclass
class Host:
    index: int  # Zero-based ReportHost occurrence within the file, for -f output.
    report_name: str
    identifiers: list = field(default_factory=list)  # (source, value) pairs
    credential_lines: list = field(default_factory=list)
    credential_tag: str = ""

    @property
    def aliases(self):
        return {normalize(value) for _, value in self.identifiers if normalize(value)}


@dataclass
class File:
    path: Path
    scan_names: list = field(default_factory=list)
    has_targets: bool = False
    targets: list = field(default_factory=list)
    hosts: list = field(default_factory=list)


def read_metadata(path):
    """Stream metadata out of XML, discarding bulky ReportItems as we go.

    Files are only returned on successful parsing, avoiding partial results
    from truncated or malformed XML documents.
    """
    result = File(path=path)
    stack = []
    report_name = "(unnamed report)"
    host = None
    host_index = 0

    for event, elem in ET.iterparse(path, events=("start", "end")):
        tag = local_name(elem.tag)
        if event == "start":
            stack.append(elem)
            if tag == "Report":
                report_name = elem.get("name") or "(unnamed report)"
                if report_name not in result.scan_names:
                    result.scan_names.append(report_name)
            elif tag == "ReportHost":
                host = Host(index=host_index, report_name=report_name)
                host_index += 1
                if elem.get("name"):
                    host.identifiers.append(("ReportHost name", elem.get("name")))
            continue

        parent = stack[-2] if len(stack) >= 2 else None
        parent_tag = local_name(parent.tag) if parent is not None else ""

        if tag == "preference" and parent_tag == "ServerPreferences":
            pref_name = child_text(elem, "name").strip()
            if pref_name.upper() == "TARGET":
                result.has_targets = True
                result.targets.extend(split_targets(child_text(elem, "value")))
            if parent is not None:
                parent.remove(elem)

        elif tag == "tag" and host is not None and parent_tag == "HostProperties":
            name = elem.get("name", "").lower()
            value = (elem.text or "").strip()
            if value:
                if name in HOST_TAGS:
                    host.identifiers.append((name, value))
                elif name == "credentialed_scan":
                    host.credential_tag = value
            if parent is not None:
                parent.remove(elem)

        elif tag == "ReportItem" and host is not None:
            if elem.get("pluginID") == "19506":
                for plugin_output in elem.iter():
                    if local_name(plugin_output.tag) == "plugin_output":
                        for line in (plugin_output.text or "").splitlines():
                            match = CRED_PATTERN.match(line)
                            if match:
                                value = match.group(1)
                                if value not in host.credential_lines:
                                    host.credential_lines.append(value)
            if parent is not None:
                parent.remove(elem)

        elif tag == "ReportHost" and host is not None:
            result.hosts.append(host)
            host = None
            if parent is not None:
                parent.remove(elem)

        elif tag == "Report":
            report_name = "(unnamed report)"
            if parent is not None:
                parent.remove(elem)

        elif tag == "Policy" and parent is not None:
            parent.remove(elem)

        stack.pop()

    # Deduplicate TARGET entries without losing order.
    result.targets = list(dict.fromkeys(result.targets))
    return result


def matches_octet_range(entry, ip):
    """Match  IPv4 ranges such as 192.168.0-1.3-5 (no expansion)."""
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    parts = entry.split(".")
    if len(parts) != 4 or "-" not in entry:
        return False
    for part, octet in zip(parts, ip.packed):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            return False
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if not (0 <= first <= octet <= last <= 255):
            return False
    return True


def match_target(raw, aliases):
    """Return (how included, matched identifier), or None.

    All match decisions use literal targets and identifiers observed in XML;
    DNS lookups are deliberately not used.
    """
    target = raw.strip().strip("\"'").strip()
    match = BRACKETED_IP.fullmatch(target)
    if match and parse_ip(match.group(2)) is not None:
        label, address = match.groups()
        for value in (address, label.strip()):
            if normalize(value) in aliases:
                return "Labeled IP (hostname[ip] syntax)", normalize(value)
        return None

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            #  also permits 'hostname/24'. Without resolution, this
            # proves only that the hostname was used to specify a subnet.
            hostname, _, mask = target.rpartition("/")
            if hostname and mask and normalize(hostname) in aliases:
                return "Hostname-based subnet", normalize(hostname)
        else:
            for alias in sorted(aliases):
                ip = parse_ip(alias)
                if ip is not None and ip in network:
                    return "IP subnet (CIDR/netmask)", alias
        return None

    if "-" in target:
        first, sep, last = target.partition("-")
        start = parse_ip(first)
        finish = parse_ip(last)
        if (sep and isinstance(start, ipaddress.IPv4Address)
                and isinstance(finish, ipaddress.IPv4Address)):
            for alias in sorted(aliases):
                ip = parse_ip(alias)
                if isinstance(ip, ipaddress.IPv4Address) and int(start) <= int(ip) <= int(finish):
                    return "IPv4 address range", alias
        for alias in sorted(aliases):
            ip = parse_ip(alias)
            if matches_octet_range(target, ip):
                return "IPv4 octet range", alias

    canonical = normalize(target)
    if canonical in aliases:
        return ("IP address" if parse_ip(target) is not None else "Hostname"), canonical
    return None


def find_correlated_aliases(query, files):
    """Discover identifiers by joining ReportHosts that share a known name/IP."""
    index = defaultdict(list)
    for scan in files:
        for host in scan.hosts:
            for alias in host.aliases:
                index[alias].append(host)

    discovered = {normalize(query)}
    queue = deque(discovered)
    visited_hosts = set()
    while queue:
        for host in index.get(queue.popleft(), ()):
            if id(host) in visited_hosts:
                continue
            visited_hosts.add(id(host))
            for alias in host.aliases - discovered:
                discovered.add(alias)
                queue.append(alias)
    return discovered


def show_identifiers(aliases):
    ips = sorted((alias for alias in aliases if parse_ip(alias) is not None))
    names = sorted((alias for alias in aliases if parse_ip(alias) is None))
    print("Known IPs:       " + (", ".join(ips) if ips else "None found"))
    print("Known hostnames: " + (", ".join(names) if names else "None found"))


def print_matches(files, aliases):
    matching = []
    for scan in files:
        matches = []
        for entry in scan.targets:
            match = match_target(entry, aliases)
            if match is not None:
                matches.append((entry, *match))
        hosts = [host for host in scan.hosts if host.aliases & aliases]
        if matches or hosts:
            matching.append((scan, matches, hosts))

    print(f"Matching files: {len(matching)} / {len(files)} readable . file(s)")
    show_identifiers(aliases)

    for scan, matches, hosts in matching:
        print("\n" + "=" * 72)
        print(f"Scan file:   {scan.path}")
        relevant_names = list(dict.fromkeys(h.report_name for h in hosts))
        if not relevant_names:
            relevant_names = scan.scan_names
        print(f"Report name: {', '.join(relevant_names) if relevant_names else '(no Report element)'}")
        if matches:
            print("In target list: Yes")
            for entry, kind, via in matches:
                print(f"  - By {kind}: {entry} (matched {via})")
        elif scan.has_targets:
            print("In target list: No matching entry")
        else:
            print("In target list: Unknown (TARGET preference missing)")

        count = len(hosts)
        section_label = "section" if count == 1 else "sections"
        print(f"ReportHost:    Yes ({count} {section_label})" if count else "ReportHost:    No")
        for host in hosts:
            hostname = next((value for source, value in host.identifiers
                             if source == "ReportHost name"), "(unnamed)")
            print(f"  - ReportHost name: {hostname} [section #{host.index + 1}]")
            extras = [(source, value) for source, value in host.identifiers
                      if source != "ReportHost name"]
            if extras:
                print("    Identifiers: " + "; ".join(f"{source}={value}" for source, value in extras))
            if host.credential_lines:
                print("    Credentialed checks (plugin 19506): " + ", ".join(host.credential_lines))
            else:
                print("    Credentialed checks (plugin 19506): Not reported")
            if host.credential_tag:
                print(f"    Credentialed_Scan (host tag): {host.credential_tag}")

    return matching


def print_full_sections(matching):
    """Second pass: emit full matching ReportHosts only, as serialized XML."""
    if not any(hosts for _, _, hosts in matching):
        return
    print("\n" + "=" * 72)
    print("FULL MATCHING REPORTHOST XML")
    for scan, _, hosts in matching:
        chosen = {host.index for host in hosts}
        if not chosen:
            continue
        stack = []
        index = -1
        current_index = -1
        for event, elem in ET.iterparse(scan.path, events=("start", "end")):
            tag = local_name(elem.tag)
            if event == "start":
                stack.append(elem)
                if tag == "ReportHost":
                    index += 1
                    current_index = index
                continue
            parent = stack[-2] if len(stack) > 1 else None
            if tag == "ReportItem" and current_index not in chosen:
                if parent is not None:
                    parent.remove(elem)
            elif tag == "ReportHost":
                if current_index in chosen:
                    print(f"\n--- File: {scan.path} | ReportHost section #{current_index + 1} ---")
                    print(ET.tostring(elem, encoding="unicode").strip())
                if parent is not None:
                    parent.remove(elem)
                current_index = -1
            elif tag in ("Policy", "Report") and parent is not None:
                parent.remove(elem)
            stack.pop()


def main():
    parser = argparse.ArgumentParser(
        description="Search . files for hosts in configured targets or ReportHost results."
    )
    parser.add_argument("target", help="IPv4/IPv6 address or hostname to look up")
    parser.add_argument("-d", "--directory", default=".", type=Path,
                        help="Directory to scan recursively (default: current directory)")
    parser.add_argument("-f", "--full", action="store_true",
                        help="Print full matching ReportHost XML sections")
    args = parser.parse_args()

    directory = args.directory.expanduser()
    if not directory.is_dir():
        parser.error(f"not a directory: {directory}")
    if not normalize(args.target):
        parser.error("target must not be empty")

    paths = sorted(p for p in directory.rglob("*") if p.suffix.lower() == "." and p.is_file())
    if not paths:
        print(f"No . files found under {directory}")
        return 1

    parsed = []
    for path in paths:
        try:
            parsed.append(read_metadata(path))
        except (ET.ParseError, OSError, UnicodeError) as exc:
            print(f"Warning: skipping {path}: {exc}", file=sys.stderr)

    if not parsed:
        print("No readable . files found.")
        return 1

    aliases = find_correlated_aliases(args.target, parsed)
    print(f"Search target: {args.target}")
    print(f"Directory:     {directory.resolve()}")
    matching = print_matches(parsed, aliases)
    if args.full and matching:
        try:
            print_full_sections(matching)
        except (ET.ParseError, OSError, UnicodeError) as exc:
            print(f"Warning: unable to print all full XML: {exc}", file=sys.stderr)
            return 2
    return 0 if matching else 1


if __name__ == "__main__":
    sys.exit(main())
