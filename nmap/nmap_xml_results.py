#!/usr/bin/env python3
"""
nmap_xml_results.py

Parse Nmap XML files recursively, merge duplicate host/port findings across scan
rounds, and summarize open ports, services, likely web targets, scanned TCP
ports, or individual hosts.

Examples:
  ./nmap_xml_results.py ports
  ./nmap_xml_results.py -d ./scans services
  ./nmap_xml_results.py -d ./scans web -o web_targets.txt
  ./nmap_xml_results.py open-port 443
  ./nmap_xml_results.py host 10.0.0.5
  ./nmap_xml_results.py --format json services
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import ipaddress
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, TextIO


DEFAULT_XML_PATTERN = "*.xml"
AGGRESSIVE_SUFFIX = "aggressive.xml"

# Broad web target generation: service names and common web-ish ports.
WEB_SERVICE_HINTS = (
    "http",
    "https",
    "http-alt",
    "http-proxy",
    "ssl/http",
    "www",
)
WEB_PORTS = {
    80,
    81,
    443,
    591,
    593,
    8000,
    8008,
    8080,
    8081,
    8082,
    8088,
    8090,
    8443,
    8834,
    8888,
    9000,
    9080,
    9090,
    9443,
    10000,
}


@dataclass(slots=True)
class SourceInfo:
    path: Path
    priority: int
    scanned_tcp_ports: set[int] = field(default_factory=set)


@dataclass(slots=True)
class ServiceInfo:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    method: str = ""
    confidence: str = ""

    def richness(self) -> int:
        """Score how much useful identification data we have."""
        score = 0
        for attr in (
            self.name,
            self.product,
            self.version,
            self.extrainfo,
            self.tunnel,
            self.ostype,
            self.method,
            self.confidence,
        ):
            if attr:
                score += 1
        # Product/version/extrainfo are usually the most useful service-scan fields.
        if self.product:
            score += 2
        if self.version:
            score += 2
        if self.extrainfo:
            score += 1
        return score

    def display(self) -> str:
        parts = [self.name]
        product_version = " ".join(x for x in (self.product, self.version) if x)
        if product_version:
            parts.append(product_version)
        if self.extrainfo:
            parts.append(f"({self.extrainfo})")
        return " ".join(p for p in parts if p).strip()

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "tunnel": self.tunnel,
            "ostype": self.ostype,
            "method": self.method,
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class PortFinding:
    host: str
    addresses: list[str]
    hostnames: list[str]
    protocol: str
    port: int
    state: str
    service: ServiceInfo
    source: Path
    source_priority: int
    all_sources: set[Path] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.all_sources.add(self.source)

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.host, self.protocol, self.port)

    def merge(self, other: "PortFinding") -> None:
        """Merge duplicate host/protocol/port findings, preferring better metadata."""
        self.all_sources.update(other.all_sources)

        self.addresses = sorted_unique([*self.addresses, *other.addresses])
        self.hostnames = sorted_unique([*self.hostnames, *other.hostnames])

        # Keep open if any duplicate saw it open.
        if self.state != "open" and other.state == "open":
            self.state = other.state

        if should_replace_service(self, other):
            self.service = other.service
            self.source = other.source
            self.source_priority = other.source_priority

    def endpoint_for_display(self, prefer_hostname: bool = False) -> str:
        if prefer_hostname and self.hostnames:
            return self.hostnames[0]
        return self.host

    def to_dict(self, show_sources: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "host": self.host,
            "addresses": self.addresses,
            "hostnames": self.hostnames,
            "protocol": self.protocol,
            "port": self.port,
            "state": self.state,
            "service": self.service.to_dict(),
            "source": str(self.source),
        }
        if show_sources:
            data["all_sources"] = sorted(str(p) for p in self.all_sources)
            data["seen_in_files"] = len(self.all_sources)
        return data


@dataclass(slots=True)
class ParseResult:
    findings: dict[tuple[str, str, int], PortFinding] = field(default_factory=dict)
    scanned_tcp_ports: set[int] = field(default_factory=set)
    parsed_files: list[Path] = field(default_factory=list)
    skipped_files: list[tuple[Path, str]] = field(default_factory=list)

    def add_finding(self, finding: PortFinding) -> None:
        existing = self.findings.get(finding.key)
        if existing is None:
            self.findings[finding.key] = finding
        else:
            existing.merge(finding)

    def open_findings(self) -> list[PortFinding]:
        return sorted(
            (f for f in self.findings.values() if f.state == "open"),
            key=lambda f: (ip_sort_key(f.host), f.protocol, f.port),
        )


# ---------- Parsing and merge helpers ----------


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted({v for v in values if v})


def ip_sort_key(value: str) -> tuple[int, Any]:
    try:
        ip = ipaddress.ip_address(value)
        return (0 if ip.version == 4 else 1, int(ip))
    except ValueError:
        return (2, value)


def is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def choose_host_identity(addresses: list[str], hostnames: list[str]) -> str | None:
    ipv4 = [a for a in addresses if is_ipv4(a)]
    if ipv4:
        return sorted(ipv4, key=ip_sort_key)[0]
    ipv6 = [a for a in addresses if is_ipv6(a)]
    if ipv6:
        return sorted(ipv6, key=ip_sort_key)[0]
    if hostnames:
        return sorted(hostnames)[0]
    return None


def source_priority(path: Path) -> int:
    name = path.name.lower()
    if name.endswith(AGGRESSIVE_SUFFIX):
        return 3
    return 1


def should_replace_service(existing: PortFinding, new: PortFinding) -> bool:
    if new.source_priority != existing.source_priority:
        return new.source_priority > existing.source_priority

    if new.service.richness() != existing.service.richness():
        return new.service.richness() > existing.service.richness()

    # If equally rich, prefer the later source lexically for deterministic output.
    return str(new.source) > str(existing.source)


def expand_ports_expression(expression: str) -> set[int]:
    """Expand an Nmap scaninfo services expression like '22,80,1000-1005'."""
    ports: set[int] = set()
    for chunk in expression.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                continue
            if 1 <= start <= end <= 65535:
                ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


def find_xml_files(directory: Path, pattern: str, recursive: bool) -> list[Path]:
    if recursive:
        candidates = directory.rglob(pattern)
    else:
        candidates = directory.glob(pattern)
    return sorted(p for p in candidates if p.is_file())


def parse_service(service_elem: ET.Element | None) -> ServiceInfo:
    if service_elem is None:
        return ServiceInfo()
    return ServiceInfo(
        name=service_elem.get("name", ""),
        product=service_elem.get("product", ""),
        version=service_elem.get("version", ""),
        extrainfo=service_elem.get("extrainfo", ""),
        tunnel=service_elem.get("tunnel", ""),
        ostype=service_elem.get("ostype", ""),
        method=service_elem.get("method", ""),
        confidence=service_elem.get("conf", ""),
    )


def parse_host(host_elem: ET.Element, src: SourceInfo, result: ParseResult) -> None:
    status_elem = host_elem.find("status")
    if status_elem is not None and status_elem.get("state") == "down":
        return

    addresses: list[str] = []
    for addr in host_elem.findall("address"):
        addr_value = addr.get("addr")
        addr_type = addr.get("addrtype", "")
        if addr_value and addr_type in {"ipv4", "ipv6", ""}:
            addresses.append(addr_value)

    hostnames = [
        h.get("name", "")
        for h in host_elem.findall("./hostnames/hostname")
        if h.get("name")
    ]
    host_identity = choose_host_identity(addresses, hostnames)
    if not host_identity:
        return

    for port_elem in host_elem.findall("./ports/port"):
        protocol = port_elem.get("protocol", "tcp")
        portid = port_elem.get("portid")
        if not portid:
            continue
        try:
            port = int(portid)
        except ValueError:
            continue

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
        service = parse_service(port_elem.find("service"))

        finding = PortFinding(
            host=host_identity,
            addresses=sorted_unique(addresses),
            hostnames=sorted_unique(hostnames),
            protocol=protocol,
            port=port,
            state=state,
            service=service,
            source=src.path,
            source_priority=src.priority,
        )
        result.add_finding(finding)


def parse_xml_file(path: Path, strict: bool = False) -> tuple[list[ET.Element], set[int]]:
    """Return host elements and scanned TCP ports from a single Nmap XML file."""
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        if strict:
            raise
        raise
    except OSError:
        if strict:
            raise
        raise

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError("not an Nmap XML file: root element is not <nmaprun>")

    scanned_tcp_ports: set[int] = set()
    for scaninfo in root.findall("scaninfo"):
        if scaninfo.get("protocol") == "tcp":
            scanned_tcp_ports.update(expand_ports_expression(scaninfo.get("services", "")))

    return list(root.findall("host")), scanned_tcp_ports


def load_results(args: argparse.Namespace) -> ParseResult:
    directory = Path(args.directory).expanduser().resolve()
    result = ParseResult()

    if not directory.exists() or not directory.is_dir():
        raise SystemExit(f"error: directory does not exist or is not a directory: {directory}")

    xml_files = find_xml_files(directory, args.pattern, args.recursive)
    if not xml_files and args.verbose:
        print(f"[!] No files matched {args.pattern!r} under {directory}", file=sys.stderr)

    for path in xml_files:
        try:
            hosts, scanned_tcp = parse_xml_file(path, strict=args.strict)
            src = SourceInfo(path=path, priority=source_priority(path), scanned_tcp_ports=scanned_tcp)
            result.scanned_tcp_ports.update(scanned_tcp)
            for host_elem in hosts:
                parse_host(host_elem, src, result)
            result.parsed_files.append(path)
            if args.verbose:
                print(f"[+] Parsed {path}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - user-facing CLI should continue by default.
            if args.strict:
                raise
            result.skipped_files.append((path, str(exc)))
            if args.verbose:
                print(f"[!] Skipped {path}: {exc}", file=sys.stderr)

    return result


# ---------- Output helpers ----------


def write_lines(lines: Iterable[str], output: str | None) -> None:
    if output:
        Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        for line in lines:
            print(line)


def emit_json(data: Any, output: str | None) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def emit_csv(rows: list[dict[str, Any]], output: str | None) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    if output:
        fh: TextIO
        with Path(output).open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def service_row_key(f: PortFinding) -> tuple[str, str, str, str, str, str]:
    return (
        f.protocol,
        str(f.port),
        f.service.name,
        f.service.product,
        f.service.version,
        f.service.extrainfo,
    )


def format_host_for_url(host: str) -> str:
    if is_ipv6(host):
        return f"[{host}]"
    return host


def is_webish(finding: PortFinding) -> bool:
    svc = finding.service
    searchable = " ".join(
        [svc.name, svc.product, svc.extrainfo, svc.tunnel]
    ).lower()
    if any(hint in searchable for hint in WEB_SERVICE_HINTS):
        return True
    if svc.tunnel.lower() in {"ssl", "tls"}:
        return True
    if finding.port in WEB_PORTS:
        return True
    if str(finding.port).endswith(("80", "443")):
        return True
    return False


def candidate_web_urls(finding: PortFinding, prefer_hostname: bool = False) -> list[str]:
    host = format_host_for_url(finding.endpoint_for_display(prefer_hostname=prefer_hostname))
    port = finding.port
    urls: list[str] = []

    if port == 80:
        urls.append(f"http://{host}")
        urls.append(f"https://{host}:80")
    elif port == 443:
        urls.append(f"https://{host}")
        urls.append(f"http://{host}:443")
    else:
        urls.append(f"http://{host}:{port}")
        urls.append(f"https://{host}:{port}")

    return urls


# ---------- Subcommands ----------


def cmd_ports(args: argparse.Namespace, result: ParseResult) -> None:
    counts: Counter[tuple[str, int]] = Counter((f.protocol, f.port) for f in result.open_findings())

    if args.format == "json":
        data = [
            {"count": count, "protocol": proto, "port": port}
            for (proto, port), count in sorted(counts.items(), key=lambda x: (-x[1], x[0][0], x[0][1]))
        ]
        emit_json(data, args.output)
        return

    if args.format == "csv":
        rows = [
            {"count": count, "protocol": proto, "port": port}
            for (proto, port), count in sorted(counts.items(), key=lambda x: (-x[1], x[0][0], x[0][1]))
        ]
        emit_csv(rows, args.output)
        return

    lines = ["count\tproto\tport"]
    lines.extend(
        f"{count}\t{proto}\t{port}"
        for (proto, port), count in sorted(counts.items(), key=lambda x: (-x[1], x[0][0], x[0][1]))
    )
    write_lines(lines, args.output)


def cmd_services(args: argparse.Namespace, result: ParseResult) -> None:
    grouped: dict[tuple[str, str, str, str, str, str], list[PortFinding]] = defaultdict(list)
    for f in result.open_findings():
        grouped[service_row_key(f)].append(f)

    rows: list[dict[str, Any]] = []
    for key, findings in grouped.items():
        proto, port, name, product, version, extrainfo = key
        row: dict[str, Any] = {
            "count": len(findings),
            "protocol": proto,
            "port": int(port),
            "service": name,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
        }
        if args.show_sources:
            row["sources"] = sorted_unique(str(f.source) for f in findings)
        rows.append(row)

    rows.sort(key=lambda r: (-int(r["count"]), str(r["protocol"]), int(r["port"]), str(r["service"])))

    if args.format == "json":
        emit_json(rows, args.output)
    elif args.format == "csv":
        emit_csv(rows, args.output)
    else:
        lines = ["count\tproto\tport\tservice\tproduct\tversion\textrainfo"]
        lines.extend(
            f"{r['count']}\t{r['protocol']}\t{r['port']}\t{r['service']}\t{r['product']}\t{r['version']}\t{r['extrainfo']}"
            for r in rows
        )
        write_lines(lines, args.output)


def cmd_web(args: argparse.Namespace, result: ParseResult) -> None:
    urls: set[str] = set()
    for finding in result.open_findings():
        if finding.protocol != "tcp":
            continue
        if not is_webish(finding):
            continue
        urls.update(candidate_web_urls(finding, prefer_hostname=args.prefer_hostname))

    sorted_urls = sorted(urls)

    if args.format == "json":
        emit_json(sorted_urls, args.output)
    elif args.format == "csv":
        emit_csv([{"url": url} for url in sorted_urls], args.output)
    else:
        write_lines(sorted_urls, args.output)


def cmd_tcp_scanned(args: argparse.Namespace, result: ParseResult) -> None:
    ports = sorted(result.scanned_tcp_ports)
    if args.format == "json":
        emit_json(ports, args.output)
    elif args.format == "csv":
        emit_csv([{"port": p} for p in ports], args.output)
    else:
        write_lines((str(p) for p in ports), args.output)


def cmd_open_port(args: argparse.Namespace, result: ParseResult) -> None:
    matches = [
        f
        for f in result.open_findings()
        if f.port == args.port and (args.protocol == "any" or f.protocol == args.protocol)
    ]
    if args.ipv4_only:
        matches = [f for f in matches if is_ipv4(f.host)]
    if args.ipv6_only:
        matches = [f for f in matches if is_ipv6(f.host)]

    if args.format == "json":
        emit_json([f.to_dict(show_sources=args.show_sources) for f in matches], args.output)
        return

    if args.format == "csv":
        rows: list[dict[str, Any]] = []
        for f in matches:
            row: dict[str, Any] = {
                "host": f.host,
                "hostnames": ",".join(f.hostnames),
                "protocol": f.protocol,
                "port": f.port,
                "service": f.service.name,
                "product": f.service.product,
                "version": f.service.version,
            }
            if args.show_sources:
                row["source"] = str(f.source)
                row["seen_in_files"] = len(f.all_sources)
            rows.append(row)
        emit_csv(rows, args.output)
        return

    lines: list[str] = []
    for f in matches:
        target = f.endpoint_for_display(prefer_hostname=args.prefer_hostname)
        if args.show_services:
            service = f.service.display()
            target = f"{target}\t{f.protocol}/{f.port}\t{service}"
        if args.show_sources:
            target = f"{target}\tsource={f.source}\tseen_in={len(f.all_sources)}"
        lines.append(target)
    write_lines(lines, args.output)


def target_matches_host(f: PortFinding, target: str) -> bool:
    target_l = target.lower()
    return (
        f.host.lower() == target_l
        or target_l in {a.lower() for a in f.addresses}
        or target_l in {h.lower() for h in f.hostnames}
    )


def cmd_host(args: argparse.Namespace, result: ParseResult) -> None:
    matches = [f for f in result.findings.values() if target_matches_host(f, args.target)]
    if not args.include_closed:
        matches = [f for f in matches if f.state == "open"]
    matches.sort(key=lambda f: (f.protocol, f.port))

    if args.format == "json":
        emit_json([f.to_dict(show_sources=args.show_sources) for f in matches], args.output)
        return

    if args.format == "csv":
        rows: list[dict[str, Any]] = []
        for f in matches:
            row: dict[str, Any] = {
                "host": f.host,
                "addresses": ",".join(f.addresses),
                "hostnames": ",".join(f.hostnames),
                "protocol": f.protocol,
                "port": f.port,
                "state": f.state,
                "service": f.service.name,
                "product": f.service.product,
                "version": f.service.version,
                "extrainfo": f.service.extrainfo,
            }
            if args.show_sources:
                row["source"] = str(f.source)
                row["seen_in_files"] = len(f.all_sources)
            rows.append(row)
        emit_csv(rows, args.output)
        return

    if not matches:
        write_lines([], args.output)
        return

    primary = matches[0]
    lines = [f"Host: {primary.host}"]
    if primary.hostnames:
        lines.append(f"Hostnames: {', '.join(primary.hostnames)}")
    if primary.addresses:
        lines.append(f"Addresses: {', '.join(primary.addresses)}")
    lines.append("")
    header = "PORT\tSTATE\tSERVICE\tVERSION"
    if args.show_sources:
        header += "\tSOURCE\tSEEN_IN"
    lines.append(header)
    for f in matches:
        version = " ".join(x for x in [f.service.product, f.service.version] if x)
        if f.service.extrainfo:
            version = f"{version} ({f.service.extrainfo})".strip()
        line = f"{f.port}/{f.protocol}\t{f.state}\t{f.service.name}\t{version}"
        if args.show_sources:
            line += f"\t{f.source}\t{len(f.all_sources)}"
        lines.append(line)
    write_lines(lines, args.output)


def cmd_files(args: argparse.Namespace, result: ParseResult) -> None:
    rows = [
        {"file": str(p), "status": "parsed", "reason": ""}
        for p in result.parsed_files
    ] + [
        {"file": str(p), "status": "skipped", "reason": reason}
        for p, reason in result.skipped_files
    ]
    rows.sort(key=lambda r: str(r["file"]))

    if args.format == "json":
        emit_json(rows, args.output)
    elif args.format == "csv":
        emit_csv(rows, args.output)
    else:
        lines = [f"{r['status']}\t{r['file']}" + (f"\t{r['reason']}" if r["reason"] else "") for r in rows]
        write_lines(lines, args.output)


# ---------- CLI ----------


def add_common_parser_options(parser: argparse.ArgumentParser, suppress_defaults: bool = False) -> None:
    default_dir = argparse.SUPPRESS if suppress_defaults else "."
    default_recursive = argparse.SUPPRESS if suppress_defaults else True
    default_pattern = argparse.SUPPRESS if suppress_defaults else DEFAULT_XML_PATTERN
    default_format = argparse.SUPPRESS if suppress_defaults else "text"
    default_none = argparse.SUPPRESS if suppress_defaults else None
    default_false = argparse.SUPPRESS if suppress_defaults else False

    parser.add_argument(
        "-d",
        "--directory",
        default=default_dir,
        help="Directory to scan for Nmap XML files. Defaults to current directory.",
    )
    parser.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=default_recursive,
        help="Search recursively. Enabled by default.",
    )
    parser.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="Only scan the top-level target directory.",
    )
    parser.add_argument(
        "--pattern",
        default=default_pattern,
        help=f"Glob pattern for XML files. Default: {DEFAULT_XML_PATTERN!r}.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "csv"),
        default=default_format,
        help="Output format. Default: text.",
    )
    parser.add_argument("-o", "--output", default=default_none, help="Write output to a file instead of stdout.")
    parser.add_argument("-v", "--verbose", action="store_true", default=default_false, help="Print parse progress/warnings to stderr.")
    parser.add_argument("--strict", action="store_true", default=default_false, help="Fail on malformed/non-Nmap XML instead of skipping.")
    parser.add_argument("--show-sources", action="store_true", default=default_false, help="Include chosen and/or merged source file information where applicable.")
    parser.add_argument("--prefer-hostname", action="store_true", default=default_false, help="Prefer hostname over IP in applicable text output and web URLs.")
    parser.add_argument("--ipv4-only", action="store_true", default=default_false, help="Only include IPv4 primary hosts where applicable.")
    parser.add_argument("--ipv6-only", action="store_true", default=default_false, help="Only include IPv6 primary hosts where applicable.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and summarize Nmap XML files, deduplicating repeated scan rounds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    add_common_parser_options(parser)
    common_parent = argparse.ArgumentParser(add_help=False)
    add_common_parser_options(common_parent, suppress_defaults=True)

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_ports = subparsers.add_parser("ports", parents=[common_parent], help="Summarize unique open ports by host count.")
    p_ports.set_defaults(func=cmd_ports)

    p_services = subparsers.add_parser("services", parents=[common_parent], help="Summarize unique open service fingerprints.")
    p_services.set_defaults(func=cmd_services)

    p_web = subparsers.add_parser("web", parents=[common_parent], help="Generate broad likely web target URL candidates.")
    p_web.set_defaults(func=cmd_web)

    p_tcp = subparsers.add_parser("tcp-scanned", aliases=["tcp_scanned"], parents=[common_parent], help="List unique TCP ports that were scanned according to XML scaninfo.")
    p_tcp.set_defaults(func=cmd_tcp_scanned)

    p_open = subparsers.add_parser("open-port", parents=[common_parent], help="List hosts with a specific open port.")
    p_open.add_argument("port", type=int, help="Open port to search for.")
    p_open.add_argument("--protocol", choices=("tcp", "udp", "sctp", "any"), default="tcp", help="Protocol to match.")
    p_open.add_argument("--show-services", action="store_true", help="Include service details in text output.")
    p_open.set_defaults(func=cmd_open_port)

    p_host = subparsers.add_parser("host", parents=[common_parent], help="Show a clean service summary for a host/IP/DNS name.")
    p_host.add_argument("target", help="IP address or hostname to summarize.")
    p_host.add_argument("--include-closed", action="store_true", help="Include non-open ports for this host.")
    p_host.set_defaults(func=cmd_host)

    p_files = subparsers.add_parser("files", parents=[common_parent], help="Show which XML files were parsed or skipped.")
    p_files.set_defaults(func=cmd_files)

    return parser


def maybe_apply_global_filters(args: argparse.Namespace, result: ParseResult) -> None:
    if args.ipv4_only and args.ipv6_only:
        raise SystemExit("error: --ipv4-only and --ipv6-only are mutually exclusive")

    if not (args.ipv4_only or args.ipv6_only):
        return

    filtered: dict[tuple[str, str, int], PortFinding] = {}
    for key, finding in result.findings.items():
        if args.ipv4_only and is_ipv4(finding.host):
            filtered[key] = finding
        elif args.ipv6_only and is_ipv6(finding.host):
            filtered[key] = finding
    result.findings = filtered


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    result = load_results(args)
    maybe_apply_global_filters(args, result)

    if args.verbose:
        print(
            f"[*] Parsed {len(result.parsed_files)} file(s), skipped {len(result.skipped_files)} file(s), "
            f"merged to {len(result.findings)} host/port finding(s).",
            file=sys.stderr,
        )

    args.func(args, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
