# PCAP report utility

`pcap_report.py` analyzes a PCAP/PCAPNG file offline and streams packets from disk, so it does not need to load the entire capture into memory.

```bash
python3 pcap_report.py capture.pcap
python3 pcap_report.py capture.pcap --top 20 --json report.json
```

The report includes:

- Protocol counts, packet and byte totals, duration, and min/max/average packet sizes.
- IPv4/IPv6 packet counts and top IPv4/IPv6 talkers.
- TCP flag-combination counts.
- Top TCP/UDP conversations, with endpoints shown in canonical order so both directions are grouped together.
- Top destination ports and DNS query names.
- Optional JSON output containing the same report data.

The script uses the project's existing Scapy dependency. Analysis is passive: it reads the capture file and does not send network traffic.
