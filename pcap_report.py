#!/usr/bin/env python3
"""Generate a compact report from a PCAP without changing the capture."""

import argparse
from collections import Counter
import json
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, PcapReader


def analyze(path):
    """Stream a PCAP and collect protocol, endpoint, port, and DNS statistics."""
    report = {
        "file": str(path),
        "packets": 0,
        "bytes": 0,
        "protocols": Counter(),
        "hosts": Counter(),
        "destination_ports": Counter(),
        "dns_queries": Counter(),
        "first_packet_time": None,
        "last_packet_time": None,
    }

    reader = PcapReader(str(path))
    try:
        for packet in reader:
            report["packets"] += 1
            report["bytes"] += len(packet)
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
                report["hosts"][ip.src] += 1
                report["hosts"][ip.dst] += 1

            if packet.haslayer(TCP):
                report["destination_ports"][str(packet[TCP].dport)] += 1
            elif packet.haslayer(UDP):
                report["destination_ports"][str(packet[UDP].dport)] += 1

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
        "protocols": dict(report["protocols"].most_common()),
        "top_talkers": ranked(report["hosts"], limit),
        "top_destination_ports": ranked(report["destination_ports"], limit),
        "top_dns_queries": ranked(report["dns_queries"], limit),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarize a PCAP: top talkers, DNS queries, and JSON export."
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

    for title, key in (
        ("Protocols", "protocols"),
        ("Top talkers (IP packet appearances)", "top_talkers"),
        ("Top destination ports", "top_destination_ports"),
        ("Top DNS queries", "top_dns_queries"),
    ):
        print(f"\n{title}:")
        values = result[key]
        if not values:
            print("  (none)")
        elif key == "protocols":
            for name, count in values.items():
                print(f"  {name:<10} {count}")
        else:
            for entry in values:
                print(f"  {entry['name']:<40} {entry['packets']}")

    if args.json_path:
        try:
            args.json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            parser.error(f"could not write JSON report: {error}")
        print(f"\nJSON report saved to {args.json_path}")


if __name__ == "__main__":
    main()
