#!/usr/bin/env python3
"""Generate a compact report from a PCAP without changing the capture."""

import argparse
from collections import Counter
import json
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, PcapReader


def _endpoint(address, port, is_ipv6):
    """Format an address/port pair without ambiguity for IPv6."""
    return f"[{address}]:{port}" if is_ipv6 else f"{address}:{port}"


def analyze(path):
    """Stream a PCAP and collect protocol, endpoint, port, and DNS statistics."""
    report = {
        "file": str(path),
        "packets": 0,
        "bytes": 0,
        "min_packet_bytes": None,
        "max_packet_bytes": 0,
        "protocols": Counter(),
        "ip_versions": Counter(),
        "tcp_flags": Counter(),
        "hosts": Counter(),
        "destination_ports": Counter(),
        "conversations": Counter(),
        "dns_queries": Counter(),
        "first_packet_time": None,
        "last_packet_time": None,
    }

    reader = PcapReader(str(path))
    try:
        for packet in reader:
            packet_size = len(packet)
            report["packets"] += 1
            report["bytes"] += packet_size
            report["min_packet_bytes"] = (
                packet_size if report["min_packet_bytes"] is None
                else min(report["min_packet_bytes"], packet_size)
            )
            report["max_packet_bytes"] = max(report["max_packet_bytes"], packet_size)

            timestamp = float(packet.time)
            if report["first_packet_time"] is None:
                report["first_packet_time"] = timestamp
            report["last_packet_time"] = timestamp

            if packet.haslayer(DNS):
                protocol = "DNS"
            elif packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            elif packet.haslayer(ARP):
                protocol = "ARP"
            else:
                protocol = "OTHER"
            report["protocols"][protocol] += 1

            if packet.haslayer(IP):
                ip = packet[IP]
                report["ip_versions"]["IPv4"] += 1
                report["hosts"][ip.src] += 1
                report["hosts"][ip.dst] += 1
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                report["ip_versions"]["IPv6"] += 1
                report["hosts"][ip.src] += 1
                report["hosts"][ip.dst] += 1

            transport = None
            if packet.haslayer(TCP):
                transport = packet[TCP]
                transport_name = "TCP"
                # CIR{P4ck3t_4n4lys1s_m4k3s_n3tw0rks_3as13r_t0_und3rst4nd}
                report["tcp_flags"][str(transport.flags) or "none"] += 1
            elif packet.haslayer(UDP):
                transport = packet[UDP]
                transport_name = "UDP"

            if transport is not None:
                source_port = transport.sport
                destination_port = transport.dport
                report["destination_ports"][str(destination_port)] += 1
                if packet.haslayer(IP):
                    source, destination = packet[IP].src, packet[IP].dst
                    is_ipv6 = False
                elif packet.haslayer(IPv6):
                    source, destination = packet[IPv6].src, packet[IPv6].dst
                    is_ipv6 = True
                else:
                    source = destination = None
                    is_ipv6 = False

                if source is not None:
                    first = (_endpoint(source, source_port, is_ipv6), source, source_port)
                    second = (_endpoint(destination, destination_port, is_ipv6), destination, destination_port)
                    left, right = sorted((first, second))
                    label = f"{transport_name} {left[0]} ↔ {right[0]}"
                    report["conversations"][label] += 1

            if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd:
                query = packet[DNS].qd
                if isinstance(query, DNSQR):
                    name = query.qname.decode("utf-8", errors="replace").rstrip(".")
                    if name:
                        report["dns_queries"][name] += 1
    finally:
        reader.close()

    first = report["first_packet_time"]
    last = report["last_packet_time"]
    report["duration_seconds"] = max(0.0, last - first) if first is not None else 0.0
    report["average_packet_bytes"] = (
        report["bytes"] / report["packets"] if report["packets"] else 0.0
    )
    return report


def ranked(counter, limit):
    return [
        {"name": name, "packets": count}
        for name, count in counter.most_common(limit)
    ]


def serializable_report(report, limit):
    return {
        "file": report["file"],
        "packets": report["packets"],
        "bytes": report["bytes"],
        "duration_seconds": round(report["duration_seconds"], 6),
        "packet_size_bytes": {
            "min": report["min_packet_bytes"],
            "max": report["max_packet_bytes"] if report["packets"] else None,
            "average": round(report["average_packet_bytes"], 2),
        },
        "protocols": dict(report["protocols"].most_common()),
        "ip_versions": dict(report["ip_versions"].most_common()),
        "tcp_flags": dict(report["tcp_flags"].most_common()),
        "top_talkers": ranked(report["hosts"], limit),
        "top_destination_ports": ranked(report["destination_ports"], limit),
        "top_conversations": ranked(report["conversations"], limit),
        "top_dns_queries": ranked(report["dns_queries"], limit),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarize a PCAP: talkers, conversations, DNS queries, and JSON export."
    )
    parser.add_argument("pcap", type=Path, help="PCAP/PCAPNG file to analyze")
    parser.add_argument(
        "--top", type=int, default=10,
        help="number of entries to show in each top list (default: 10)",
    )
    parser.add_argument("--json", dest="json_path", type=Path,
                        help="also write the report to this JSON file")
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")
    if not args.pcap.is_file():
        parser.error(f"PCAP file not found: {args.pcap}")

    try:
        report = analyze(args.pcap)
    except (OSError, EOFError, ValueError) as error:
        parser.error(f"could not read PCAP: {error}")

    result = serializable_report(report, args.top)
    print(f"PCAP report: {result['file']}")
    print(f"Packets: {result['packets']}  Bytes: {result['bytes']}  "
          f"Duration: {result['duration_seconds']:.3f}s")
    sizes = result["packet_size_bytes"]
    if sizes["min"] is not None:
        print(f"Packet sizes: min {sizes['min']} B, max {sizes['max']} B, "
              f"average {sizes['average']} B")

    for title, key in (
        ("Protocols", "protocols"),
        ("IP versions", "ip_versions"),
        ("TCP flag combinations", "tcp_flags"),
        ("Top talkers (IPv4/IPv6 packet appearances)", "top_talkers"),
        ("Top destination ports", "top_destination_ports"),
        ("Top conversations (TCP/UDP)", "top_conversations"),
        ("Top DNS queries", "top_dns_queries"),
    ):
        print(f"\n{title}:")
        values = result[key]
        if not values:
            print("  (none)")
        elif key in ("protocols", "ip_versions", "tcp_flags"):
            for name, count in values.items():
                print(f"  {name:<10} {count}")
        else:
            for entry in values:
                print(f"  {entry['name']:<60} {entry['packets']}")

    if args.json_path:
        try:
            args.json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            parser.error(f"could not write JSON report: {error}")
        print(f"\nJSON report saved to {args.json_path}")


if __name__ == "__main__":
    main()
