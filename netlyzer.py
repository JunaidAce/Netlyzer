#!/usr/bin/env python3
"""
Netlyzer - Network Protocol Analyzer
CLI packet analysis tool
"""

import argparse
import sys
import os
import signal
import time
from datetime import datetime
from collections import defaultdict

from scapy.all import (
    sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, Ether,
    get_if_list, Dot1Q, DHCP, Raw
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.utils import PcapWriter

try:
    from scapy.contrib.ospf import OSPF_Hdr
    OSPF_AVAILABLE = True
except ImportError:
    OSPF_AVAILABLE = False

from colorama import Fore, Style, init
init(autoreset=True)

sys.stdout.reconfigure(line_buffering=True)

# ──────────────────────────────────────────
#  Color Palette

R  = Style.RESET_ALL
B  = Style.BRIGHT

C_TCP   = Fore.CYAN
C_UDP   = Fore.GREEN
C_ICMP  = Fore.YELLOW
C_DNS   = Fore.MAGENTA
C_HTTP  = Fore.BLUE
C_ARP   = Fore.WHITE
C_FTP   = Fore.LIGHTYELLOW_EX
C_SSH   = Fore.LIGHTBLUE_EX
C_DHCP  = Fore.LIGHTGREEN_EX
C_VLAN  = Fore.LIGHTMAGENTA_EX
C_OTHER = Fore.RED

C_SRC   = Fore.GREEN
C_DST   = Fore.RED
C_HEAD  = Fore.CYAN  + B
C_INFO  = Fore.CYAN
C_OK    = Fore.GREEN + B
C_WARN  = Fore.YELLOW
C_ALERT = Fore.RED   + B
C_DIM   = Fore.WHITE

# Prefix tags  (meth-style)
TAG_INFO  = f"{C_INFO}[*]{R}"   # general info / status
TAG_FOUND = f"{C_OK}[+]{R}"     # something discovered / success
TAG_ALERT = f"{C_ALERT}[!]{R}"  # security alert / error
TAG_RESP  = f"{C_WARN}[=]{R}"   # response / reply data
TAG_DATA  = f"{C_DST}[>]{R}"    # raw data / payload
TAG_OUT   = f"{C_DIM}[-]{R}"    # outbound / minor info

# TCP flag map
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST',
    'P': 'PSH', 'A': 'ACK', 'U': 'URG',
    'E': 'ECE', 'C': 'CWR'
}

PROTO_COLOR = {
    "TCP":      C_TCP,
    "UDP":      C_UDP,
    "ICMP":     C_ICMP,
    "DNS":      C_DNS,
    "HTTP":     C_HTTP,
    "ARP":      C_ARP,
    "FTP":      C_FTP,
    "SSH/SFTP": C_SSH,
    "DHCP":     C_DHCP,
}


# ──────────────────────────────────────────
#  Banner

def banner():
    print(fr"""
{Fore.CYAN + B}
_____   __    ___________                          
___  | / /______  /___  /____  ____________________
__   |/ /_  _ \  __/_  /__  / / /__  /_  _ \_  ___/
_  /|  / /  __/ /_ _  / _  /_/ /__  /_/  __/  /    
/_/ |_/  \___/\__/ /_/  _\__, / _____/\___//_/     
                        /____/                     
{C_INFO}[*]{R} Network Protocol Analyzer
{C_DIM}{"─" * 44}{R}""")


# ──────────────────────────────────────────
#  Logging helpers
# ──────────────────────────────────────────

def log_info(msg):
    print(f"{TAG_INFO} {msg}")

def log_found(msg):
    print(f"{TAG_FOUND} {msg}")

def log_alert(msg):
    print(f"\n{TAG_ALERT} {msg}")

def log_resp(msg):
    print(f"    {TAG_RESP} {msg}")

def log_data(msg):
    print(f"    {TAG_DATA} {msg}")

def log_out(msg):
    print(f"    {TAG_OUT} {msg}")

def section(title):
    print(f"\n{C_HEAD}{'─' * 10} {title} {'─' * (33 - len(title))}{R}")


# ──────────────────────────────────────────
#  Packet Statistics
# ──────────────────────────────────────────

class PacketStats:
    def __init__(self):
        self.total_packets    = 0
        self.protocol_counts  = defaultdict(int)
        self.port_counts      = defaultdict(int)
        self.packet_sizes     = []
        self.start_time       = datetime.now()
        self.arp_hosts        = {}               # ip -> {mac, type}
        self.vlan_ids         = defaultdict(int) # vlan_id -> frame count
        self._iface           = "eth0"

    def detect_protocol(self, packet):
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return "HTTP"
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(DHCP):
            return "DHCP"
        if packet.haslayer(TCP):
            if packet.haslayer(Raw):
                dp = packet[TCP].dport
                sp = packet[TCP].sport
                if dp in (20, 21) or sp in (20, 21):
                    return "FTP"
                if dp == 22 or sp == 22:
                    return "SSH/SFTP"
            return "TCP"
        if packet.haslayer(UDP):  return "UDP"
        if packet.haslayer(ICMP): return "ICMP"
        if packet.haslayer(ARP):  return "ARP"
        return "OTHER"

    def update(self, packet):
        self.total_packets += 1
        self.packet_sizes.append(len(packet))
        proto = self.detect_protocol(packet)
        self.protocol_counts[proto] += 1

        if packet.haslayer(TCP):
            self.port_counts[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            self.port_counts[packet[UDP].dport] += 1

        if packet.haslayer(ARP):
            ip  = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            op  = packet[ARP].op
            if ip and ip != "0.0.0.0":
                self.arp_hosts[ip] = {
                    "mac":  mac,
                    "type": "ARP-Request" if op == 1 else "ARP-Reply"
                }

        if packet.haslayer(Dot1Q):
            self.vlan_ids[packet[Dot1Q].vlan] += 1

    def print_summary(self):
        dur = (datetime.now() - self.start_time).total_seconds()
        section("CAPTURE SUMMARY")
        log_info(f"Total Packets  : {Fore.YELLOW}{self.total_packets}{R}")
        log_info(f"Duration       : {Fore.YELLOW}{dur:.2f}s{R}")
        if dur > 0:
            log_info(f"Rate           : {Fore.YELLOW}{self.total_packets/dur:.1f} pkt/s{R}")
        if self.packet_sizes:
            avg = sum(self.packet_sizes) / len(self.packet_sizes)
            log_info(f"Avg Pkt Size   : {Fore.YELLOW}{avg:.0f} bytes{R}")

        section("PROTOCOL BREAKDOWN")
        for proto, cnt in sorted(self.protocol_counts.items(), key=lambda x: -x[1]):
            color = PROTO_COLOR.get(proto, C_OTHER)
            print(f"    {color}{proto:<10}{R}  {Fore.YELLOW}{cnt:>5}{R}")

        if self.port_counts:
            section("TOP DESTINATION PORTS")
            for port, cnt in sorted(self.port_counts.items(), key=lambda x: -x[1])[:10]:
                log_out(f"Port {Fore.CYAN}{port:<6}{R}  {Fore.YELLOW}{cnt}{R} packets")

        if self.arp_hosts:
            section(f"ARP HOSTS DISCOVERED  ({len(self.arp_hosts)})")
            print(f"    {C_HEAD}{'IP Address':<20} {'MAC Address':<20} Type{R}")
            print(f"    {'─'*18}  {'─'*18}  {'─'*12}")
            for ip, info in sorted(self.arp_hosts.items()):
                print(f"    {C_SRC}{ip:<20}{R} {Fore.CYAN}{info['mac']:<20}{R} {C_DIM}{info['type']}{R}")

        if self.vlan_ids:
            section(f"VLAN SEGMENTS  ({len(self.vlan_ids)})")
            print(f"    {C_HEAD}{'VLAN ID':<10} {'Frames':<8} How to Join{R}")
            print(f"    {'─'*8}  {'─'*6}  {'─'*28}")
            for vid, cnt in sorted(self.vlan_ids.items()):
                print(f"    {C_VLAN}{vid:<10}{R} {Fore.YELLOW}{cnt:<8}{R} sudo vconfig add {self._iface} {vid}")

        print()


# ──────────────────────────────────────────
#  Security Alert Engine  (Above-inspired)
# ──────────────────────────────────────────

class SecurityAlerts:
    LLMNR_MC = "224.0.0.252"
    MDNS_MC  = "224.0.0.251"
    SSDP_MC  = "239.255.255.250"

    def __init__(self):
        self.seen = set()

    def _fire(self, tag, impact, tools, details, mitigation):
        if tag in self.seen:
            return
        self.seen.add(tag)
        log_alert(f"Detected {C_ALERT}{tag}{R}")
        log_resp( f"Impact     : {Fore.YELLOW}{impact}{R}")
        log_resp( f"Tools      : {Fore.CYAN}{tools}{R}")
        for k, v in details.items():
            log_out(f"{k:<12}: {Fore.WHITE}{v}{R}")
        log_resp(f"Mitigation : {C_OK}{mitigation}{R}")
        print()

    def check(self, packet):
        self._stp(packet)
        self._ospf(packet)
        self._hsrp(packet)
        self._vrrp(packet)
        self._llmnr(packet)
        self._mdns(packet)
        self._nbt_ns(packet)
        self._dhcp(packet)
        self._cdp(packet)
        self._vlan(packet)
        self._ssdp(packet)

    def _stp(self, packet):
        if packet.haslayer(Ether) and packet[Ether].dst.lower() == "01:80:c2:00:00:00":
            self._fire(
                "STP Frame",
                "Partial MITM via Root Bridge hijack",
                "Yersinia, Scapy",
                {"Sender MAC": packet[Ether].src},
                "Enable BPDU Guard / PortFast on access ports"
            )

    def _ospf(self, packet):
        is_ospf = (OSPF_AVAILABLE and packet.haslayer(OSPF_Hdr)) or \
                  (packet.haslayer(IP) and packet[IP].proto == 89)
        if is_ospf:
            src = packet[IP].src if packet.haslayer(IP) else "?"
            self._fire(
                "OSPF Packet",
                "Routing table manipulation / blackhole",
                "Loki, FRRouting, Scapy",
                {"Sender IP": src},
                "Enable OSPF MD5/SHA authentication"
            )

    def _hsrp(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 1985:
            src = packet[IP].src if packet.haslayer(IP) else "?"
            self._fire(
                "HSRP Packet",
                "MITM via active router takeover",
                "Loki, Scapy, Yersinia",
                {"Sender IP": src},
                "Priority 255, MD5 auth, restrict via ACL"
            )

    def _vrrp(self, packet):
        if packet.haslayer(IP) and packet[IP].proto == 112:
            self._fire(
                "VRRP Packet",
                "MITM via master takeover",
                "Scapy, Loki",
                {"Sender IP": packet[IP].src},
                "Enable VRRP authentication"
            )

    def _llmnr(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 5355:
            if packet.haslayer(IP) and packet[IP].dst == self.LLMNR_MC:
                self._fire(
                    "LLMNR Query",
                    "Credential theft via LLMNR poisoning",
                    "Responder",
                    {"Sender IP": packet[IP].src},
                    "Disable LLMNR via GPO; enforce DNS"
                )

    def _mdns(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 5353:
            if packet.haslayer(IP) and packet[IP].dst == self.MDNS_MC:
                self._fire(
                    "mDNS Query",
                    "Credential theft / host enumeration",
                    "Responder",
                    {"Sender IP": packet[IP].src},
                    "Disable mDNS or restrict with firewall"
                )

    def _nbt_ns(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 137:
            src = packet[IP].src if packet.haslayer(IP) else "?"
            self._fire(
                "NBT-NS Query",
                "Credential theft via NBT-NS poisoning",
                "Responder",
                {"Sender IP": src},
                "Disable NetBIOS over TCP/IP in Windows"
            )

    def _dhcp(self, packet):
        if packet.haslayer(DHCP):
            mt = None
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'message-type':
                    mt = opt[1]
            label = {1:"Discover",2:"Offer",3:"Request",5:"ACK"}.get(mt, f"type={mt}")
            mac = packet[Ether].src if packet.haslayer(Ether) else "?"
            self._fire(
                f"DHCP {label}",
                "DHCP starvation / rogue server injection",
                "Yersinia, DHCPig",
                {"Sender MAC": mac},
                "Enable DHCP Snooping on switches"
            )

    def _cdp(self, packet):
        if packet.haslayer(Ether) and packet[Ether].dst.lower() == "01:00:0c:cc:cc:cc":
            self._fire(
                "CDP Frame (Cisco Discovery Protocol)",
                "Topology leakage / CDP flood",
                "Yersinia, Scapy",
                {"Sender MAC": packet[Ether].src},
                "Disable CDP on untrusted/edge interfaces"
            )

    def _vlan(self, packet):
        if packet.haslayer(Dot1Q):
            vid = packet[Dot1Q].vlan
            self._fire(
                f"802.1Q VLAN Tag  ID={vid}",
                "VLAN hopping if DTP is enabled",
                "Yersinia",
                {"VLAN ID": vid},
                "Disable DTP; set trunk ports explicitly"
            )

    def _ssdp(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 1900:
            if packet.haslayer(IP) and packet[IP].dst == self.SSDP_MC:
                self._fire(
                    "SSDP / UPnP Discovery",
                    "UPnP exploitation / network enumeration",
                    "Miranda, Scapy",
                    {"Sender IP": packet[IP].src},
                    "Disable UPnP on all routers and devices"
                )


# ──────────────────────────────────────────
#  Live table helpers
# ──────────────────────────────────────────

def _arp_table(hosts):
    os.system('clear')
    print(f"{C_OK}[+] Passive ARP Host Discovery{R}\n")
    print(f"  {C_HEAD}{'IP Address':<20} {'MAC Address':<20} Type{R}")
    print(f"  {'─'*18}  {'─'*18}  {'─'*12}")
    for ip, d in sorted(hosts.items()):
        print(f"  {C_SRC}{ip:<20}{R} {Fore.CYAN}{d['mac']:<20}{R} {C_DIM}{d['type']}{R}")

def _vlan_table(vlan_ids, iface):
    os.system('clear')
    print(f"{C_VLAN}[+] VLAN Segment Discovery{R}\n")
    print(f"  {C_HEAD}{'VLAN ID':<10} {'Frames':<8} How to Join{R}")
    print(f"  {'─'*8}  {'─'*6}  {'─'*30}")
    for vid, cnt in sorted(vlan_ids.items()):
        print(f"  {C_VLAN}{vid:<10}{R} {Fore.YELLOW}{cnt:<8}{R} sudo vconfig add {iface} {vid}")


# ──────────────────────────────────────────
#  Main Analyzer
# ──────────────────────────────────────────

class Netlyzer:

    def __init__(self, args):
        self.args       = args
        self.stats      = PacketStats()
        self.stats._iface = args.interface or "eth0"
        self.alerts     = SecurityAlerts()
        self.pcap_writer = None
        self._stop_time  = None

        if args.write:
            self.pcap_writer = PcapWriter(args.write, append=True, sync=True)
        if getattr(args, 'timer', None):
            self._stop_time = time.time() + args.timer

        signal.signal(signal.SIGINT, self._sig_handler)

    def _sig_handler(self, sig, frame):
        print(f"\n{TAG_ALERT} Capture interrupted by user.")
        self.stats.print_summary()
        sys.exit(0)

    # ── Formatting ──────────────────────────

    def _proto(self, packet):
        return self.stats.detect_protocol(packet)

    def _tcp_flags(self, packet):
        raw = packet.sprintf('%TCP.flags%')
        parts = [TCP_FLAGS[f] for f in raw if f in TCP_FLAGS]
        return "-".join(parts) if parts else ""

    def _http_lines(self, packet):
        lines = []
        if packet.haslayer(HTTPRequest):
            try:
                method = packet[HTTPRequest].Method.decode()
                host   = packet[HTTPRequest].Host.decode()
                path   = packet[HTTPRequest].Path.decode()
                lines.append(f"{TAG_RESP} {C_HTTP}HTTP {method}{R}  {Fore.CYAN}{host}{R}{path}")
                if method == "POST" and packet.haslayer(Raw):
                    try:
                        body = packet[Raw].load.decode(errors='replace')
                        lines.append(f"{TAG_DATA} {C_ALERT}POST Payload{R} → {body}")
                    except Exception:
                        pass
            except Exception:
                pass
        elif packet.haslayer(HTTPResponse):
            try:
                status = packet[HTTPResponse].Status_Code.decode()
                phrase = packet[HTTPResponse].Reason_Phrase.decode()
                lines.append(f"{TAG_RESP} {C_HTTP}HTTP{R}  {Fore.YELLOW}{status}{R} {phrase}")
            except Exception:
                pass
        return lines

    def _format(self, packet):
        ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        proto = self._proto(packet)
        color = PROTO_COLOR.get(proto, C_OTHER)

        vlan_tag = ""
        if packet.haslayer(Dot1Q):
            vlan_tag = f" {C_VLAN}[VLAN {packet[Dot1Q].vlan}]{R}"

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            sz  = len(packet)

            if packet.haslayer(TCP):
                sp    = packet[TCP].sport
                dp    = packet[TCP].dport
                flags = self._tcp_flags(packet)
                ftag  = f" {Fore.YELLOW}[{flags}]{R}" if flags else ""
                return (
                    f"{C_DIM}{ts}{R}  {TAG_INFO} {color}{proto:<8}{R}{vlan_tag}  "
                    f"{C_SRC}{src}:{sp}{R} → {C_DST}{dst}:{dp}{R}  "
                    f"{C_DIM}len={sz}{R}{ftag}"
                )

            if packet.haslayer(UDP):
                sp = packet[UDP].sport
                dp = packet[UDP].dport
                return (
                    f"{C_DIM}{ts}{R}  {TAG_INFO} {color}{proto:<8}{R}{vlan_tag}  "
                    f"{C_SRC}{src}:{sp}{R} → {C_DST}{dst}:{dp}{R}  "
                    f"{C_DIM}len={sz}{R}"
                )

            if packet.haslayer(ICMP):
                return (
                    f"{C_DIM}{ts}{R}  {TAG_INFO} {color}{proto:<8}{R}{vlan_tag}  "
                    f"{C_SRC}{src}{R} → {C_DST}{dst}{R}"
                )

        if packet.haslayer(ARP):
            op  = "Who-has" if packet[ARP].op == 1 else "Is-at"
            return (
                f"{C_DIM}{ts}{R}  {TAG_INFO} {color}ARP{R}{vlan_tag}  "
                f"{op}  {C_SRC}{packet[ARP].psrc}{R} [{Fore.CYAN}{packet[ARP].hwsrc}{R}] "
                f"→ {C_DST}{packet[ARP].pdst}{R}"
            )

        return f"{C_DIM}{ts}{R}  {TAG_OUT} {color}{proto}{R}{vlan_tag}"

    # ── Packet handler ───────────────────────

    def handle(self, packet):
        if self._stop_time and time.time() >= self._stop_time:
            log_info("Timer expired.")
            self.stats.print_summary()
            sys.exit(0)

        self.stats.update(packet)
        self.alerts.check(packet)

        passive_arp  = getattr(self.args, 'passive_arp',  False)
        search_vlan  = getattr(self.args, 'search_vlan',  False)

        if self.args.verbose >= 2:
            packet.show()
        elif not passive_arp and not search_vlan:
            print(self._format(packet))
            for line in self._http_lines(packet):
                print(line)

        if passive_arp and packet.haslayer(ARP):
            _arp_table(self.stats.arp_hosts)
        if search_vlan and packet.haslayer(Dot1Q):
            _vlan_table(self.stats.vlan_ids, self.args.interface or "eth0")

        if self.pcap_writer:
            self.pcap_writer.write(packet)

    # ── Modes ────────────────────────────────

    def cold_mode(self):
        log_info(f"Cold mode — reading {Fore.CYAN}{self.args.input}{R}")
        try:
            packets = rdpcap(self.args.input)
        except Exception as e:
            log_alert(f"Failed to read PCAP: {e}")
            sys.exit(1)
        log_found(f"Loaded {Fore.YELLOW}{len(packets)}{R} packets\n")
        for pkt in packets:
            self.handle(pkt)
        self.stats.print_summary()

    def _bpf(self):
        parts = []
        if self.args.protocol: parts.append(self.args.protocol.lower())
        if self.args.port:     parts.append(f"port {self.args.port}")
        if self.args.src:      parts.append(f"src host {self.args.src}")
        if self.args.dst:      parts.append(f"dst host {self.args.dst}")
        if self.args.filter:   parts.append(self.args.filter)
        return " and ".join(parts) if parts else None

    def start(self):
        bpf   = self._bpf()
        timer = getattr(self.args, 'timer', None)

        print(f"{C_INFO}[*]{R} Interface : {Fore.CYAN}{self.args.interface}{R}")
        print(f"{C_INFO}[*]{R} BPF Filter: {Fore.CYAN}{bpf or 'none'}{R}")
        print(f"{C_INFO}[*]{R} Count     : {Fore.CYAN}{self.args.count or 'unlimited'}{R}")
        print(f"{C_INFO}[*]{R} Timer     : {Fore.CYAN}{f'{timer}s' if timer else 'none'}{R}")
        if getattr(self.args, 'passive_arp', False):
            log_found("Mode: Passive ARP Discovery")
        if getattr(self.args, 'search_vlan', False):
            log_found("Mode: VLAN Segment Search")
        if self.args.write:
            log_found(f"Writing PCAP → {Fore.CYAN}{self.args.write}{R}")
        print(f"{C_DIM}{'─'*44}{R}\n")

        log_info("Sniffing has begun ...\n")

        try:
            sniff(
                iface=self.args.interface,
                prn=self.handle,
                filter=bpf,
                store=False,
                count=self.args.count or 0
            )
        except PermissionError:
            log_alert("Permission denied — run with sudo.")
            sys.exit(1)

        self.stats.print_summary()


# ──────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────

def list_interfaces():
    section("AVAILABLE INTERFACES")
    for iface in get_if_list():
        log_found(f"{Fore.CYAN}{iface}{R}")
    print()


# ──────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Netlyzer — Network Protocol Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-i", "--interface", default="any",
                        help="Network interface  (default: any)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available interfaces and exit")
    parser.add_argument("-c", "--count", type=int,
                        help="Packet capture limit  (default: unlimited)")
    parser.add_argument("-w", "--write",
                        help="Save captured traffic to .pcap file")
    parser.add_argument("-p", "--protocol",
                        help="Filter by protocol  (tcp/udp/icmp/arp)")
    parser.add_argument("--port", type=int,
                        help="Filter by destination port")
    parser.add_argument("--src",
                        help="Filter by source IP")
    parser.add_argument("--dst",
                        help="Filter by destination IP")
    parser.add_argument("--filter",
                        help="Raw BPF filter string")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v  show summary  |  -vv  full packet dump")
    parser.add_argument("--timer", type=int,
                        help="Auto-stop after N seconds")
    parser.add_argument("--input",
                        help="Analyze existing .pcap file (cold mode)")
    parser.add_argument("--passive-arp", action="store_true",
                        help="Passive ARP host discovery (no noise)")
    parser.add_argument("--search-vlan", action="store_true",
                        help="Discover 802.1Q VLAN segments")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    tool = Netlyzer(args)

    if args.input:
        tool.cold_mode()
        return

    tool.start()


if __name__ == "__main__":
    main()
           
