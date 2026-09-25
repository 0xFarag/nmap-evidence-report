#!/usr/bin/env python3
"""Summarize local Nmap XML as deterministic Markdown or JSON. Never runs a scan."""

import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from xml.parsers import expat

MAX_BYTES = 5 * 1024 * 1024
MAX_ELEMENTS = 100_000
MAX_DEPTH = 64


class InputError(ValueError):
    pass


def guarded_xml(raw):
    """Bounded Expat -> ElementTree builder, rejecting internal DTDs/entities.

    Ordinary Nmap DOCTYPE declarations are accepted. External DTDs are never
    resolved, parameter entity parsing is disabled, and entity declarations are
    refused. This is a small offline parser, not a general XML security gateway.
    """
    if len(raw) > MAX_BYTES:
        raise InputError("XML exceeds the 5 MiB input limit")
    # Current Expat mitigates known large-token quadratic parsing behavior.
    if expat.version_info < (2, 6, 0):
        raise InputError("Expat 2.6.0 or newer is required; update Python")
    parser = expat.ParserCreate()
    builder = ET.TreeBuilder()
    depth = 0
    count = 0

    def start(name, attributes):
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > MAX_DEPTH or count > MAX_ELEMENTS:
            raise InputError("XML structural limit exceeded")
        builder.start(name, attributes)

    def end(name):
        nonlocal depth
        builder.end(name)
        depth -= 1

    def doctype(name, _system_id, _public_id, internal_subset):
        if name != "nmaprun" or internal_subset:
            raise InputError("only a nmaprun DOCTYPE without internal subset is allowed")

    def reject_entity(*_args):
        raise InputError("entity declarations and external entities are not allowed")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = reject_entity
    parser.ExternalEntityRefHandler = reject_entity
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(raw, True)
        root = builder.close()
    except (expat.ExpatError, ET.ParseError) as exc:
        raise InputError(f"invalid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise InputError("root element must be nmaprun")
    return root


def parse_report(raw):
    root = guarded_xml(raw)
    hosts = []
    for host in root.findall("host"):
        addresses = []
        for address in host.findall("address"):
            if address.get("addrtype") not in {"ipv4", "ipv6"}:
                continue
            try:
                ip = ipaddress.ip_address(address.get("addr", ""))
            except ValueError as exc:
                raise InputError("host contains an invalid IP address") from exc
            if (ip.version == 4) != (address.get("addrtype") == "ipv4"):
                raise InputError("IP address family does not match addrtype")
            addresses.append(str(ip))
        ports = []
        for port in host.findall("ports/port"):
            port_id = port.get("portid", "")
            if not re.fullmatch(r"[0-9]{1,5}", port_id) or int(port_id) > 65535:
                raise InputError("portid must be an integer between 0 and 65535")
            protocol = port.get("protocol", "")
            if protocol not in {"tcp", "udp", "sctp", "ip"}:
                raise InputError("unsupported or missing port protocol")
            state = port.find("state")
            service = port.find("service")
            ports.append({"port": int(port_id), "protocol": protocol,
                          "state": state.get("state", "unknown") if state is not None else "unknown",
                          "service": {key: service.get(key, "") if service is not None else ""
                                      for key in ("name", "product", "version", "extrainfo", "method", "conf")}})
        status = host.find("status")
        # Script bodies, hostnames, command-line arguments and MAC addresses are
        # deliberately omitted: they are outside this service inventory's scope.
        hosts.append({"addresses": sorted(set(addresses)),
                      "status": status.get("state", "unknown") if status is not None else "unknown",
                      "ports": sorted(ports, key=lambda item: (item["protocol"], item["port"]))})
    hosts.sort(key=lambda item: (item["addresses"], item["status"],
                                 json.dumps(item["ports"], sort_keys=True)))
    return {"schema_version": 1, "source_sha256": hashlib.sha256(raw).hexdigest(),
            "scanner": root.get("scanner", "unknown"),
            "scanner_version": root.get("version", "unknown"),
            "hosts": hosts,
            "summary": {"hosts_in_xml": len(hosts),
                        "explicit_port_records": sum(len(h["ports"]) for h in hosts),
                        "open_port_records": sum(p["state"] == "open" for h in hosts for p in h["ports"])},
            "limitations": ["Service observations are not confirmed vulnerabilities.",
                            "Only explicit host/ports/port entries are listed; extraports are omitted.",
                            "This tool does not run scans, resolve names or fetch external XML resources.",
                            "Addresses and banners can be sensitive: review before sharing."]}


def markdown_cell(value):
    """Neutralize raw HTML, Markdown links/images and table/newline injection."""
    value = " ".join(str(value).split())
    value = html.escape(value, quote=False)
    for char in "\\`*_{}[]()!":
        value = value.replace(char, "\\" + char)
    return value.replace("|", "&#124;")


def to_markdown(report):
    summary = report["summary"]
    lines = ["# Nmap service inventory", "",
             "> Observations only. Open ports and version banners do not establish a vulnerability.", "",
             f"- Hosts represented: {summary['hosts_in_xml']}",
             f"- Explicit port records: {summary['explicit_port_records']}",
             f"- Open port records: {summary['open_port_records']}",
             f"- Input SHA-256: `{report['source_sha256']}`", "",
             "| Address | Host state | Port | State | Service | Product / version | Detection |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for host in report["hosts"]:
        address = ", ".join(host["addresses"]) or "not reported"
        for port in host["ports"]:
            service = port["service"]
            banner = " ".join(service[k] for k in ("product", "version", "extrainfo") if service[k])
            method = service["method"] or "not reported"
            if service["conf"]:
                method += f"; confidence={service['conf']}"
            cells = (address, host["status"], f"{port['port']}/{port['protocol']}",
                     port["state"], service["name"] or "not reported", banner or "not reported", method)
            lines.append("| " + " | ".join(map(markdown_cell, cells)) + " |")
        if not host["ports"]:
            lines.append("| " + " | ".join(map(markdown_cell, (address, host["status"], "none listed", "-", "-", "-", "-"))) + " |")
    lines += ["", "## Interpretation limits", ""]
    lines.extend("- " + item for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="local Nmap XML (at most 5 MiB)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="new output file; existing files are preserved")
    args = parser.parse_args(argv)
    try:
        with args.input.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        report = parse_report(raw)
        rendered = to_markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as target:
                target.write(rendered)
        else:
            print(rendered, end="")
    except (OSError, InputError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
