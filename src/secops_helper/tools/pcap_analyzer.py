#!/usr/bin/env python3
"""
PCAP Analyzer - Analyze network traffic from PCAP files
Supports protocol analysis, session reconstruction, and threat detection
"""

import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from collections import Counter, defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, DNSQR, DNSRR

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    rdpcap = None
    IP = None
    TCP = None
    UDP = None
    DNS = None
    Raw = None
    DNSQR = None
    DNSRR = None


class PCAPAnalyzer:
    """Main PCAP analysis class"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.packets = []
        self.stats = {
            "total_bytes": 0,
            "protocols": defaultdict(int),
            "src_ips": set(),
            "dst_ips": set(),
            "syn_packets": defaultdict(int),
            "dst_ports": defaultdict(int),
            "dns_queries": defaultdict(int),
        }
        self.conversations = defaultdict(int)
        self.alerts = []

    def load_pcap(self, pcap_file: str) -> bool:
        """Load PCAP file"""
        if not SCAPY_AVAILABLE:
            print(
                "Error: scapy library not installed. Install with: pip install scapy",
                file=sys.stderr,
            )
            return False

        if not Path(pcap_file).exists():
            print(f"Error: File not found: {pcap_file}", file=sys.stderr)
            return False

        try:
            if self.verbose:
                print(f"Loading PCAP file: {pcap_file}", file=sys.stderr)

            self.packets = rdpcap(pcap_file)

            if self.verbose:
                print(f"Loaded {len(self.packets)} packets", file=sys.stderr)

            return True

        except Exception as e:
            print(f"Error loading PCAP: {e}", file=sys.stderr)
            return False

    def analyze(self) -> Dict:
        """Analyze loaded packets"""
        if not self.packets:
            return {"error": "No packets loaded"}

        if self.verbose:
            print("Analyzing packets...", file=sys.stderr)

        # Analyze each packet
        for i, packet in enumerate(self.packets, 1):
            if self.verbose and i % 1000 == 0:
                print(f"Processed {i}/{len(self.packets)} packets...", file=sys.stderr)

            self._analyze_packet(packet)

        # Generate results
        results = {
            "metadata": {
                "total_packets": len(self.packets),
                "analysis_date": datetime.now().isoformat(),
            },
            "summary": {
                "protocols": dict(self.stats["protocols"]),
                "total_bytes": self.stats["total_bytes"],
                "unique_src_ips": len(self.stats["src_ips"]),
                "unique_dst_ips": len(self.stats["dst_ips"]),
                "total_alerts": len(self.alerts),
            },
            "statistics": self._generate_statistics(),
            "alerts": self.alerts[:100],  # Limit to 100 alerts
        }

        return results

    def _analyze_packet(self, packet):
        """Analyze a single packet"""
        # Count total bytes
        self.stats["total_bytes"] += len(packet)

        # Check if IP packet
        if not packet.haslayer(IP):
            self.stats["protocols"]["non-ip"] += 1
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Track IPs
        self.stats["src_ips"].add(src_ip)
        self.stats["dst_ips"].add(dst_ip)

        # Analyze protocol
        if packet.haslayer(TCP):
            self._analyze_tcp(packet, src_ip, dst_ip)
        elif packet.haslayer(UDP):
            self._analyze_udp(packet, src_ip, dst_ip)
        else:
            self.stats["protocols"]["other"] += 1

    def _analyze_tcp(self, packet, src_ip: str, dst_ip: str):
        """Analyze TCP packet"""
        self.stats["protocols"]["TCP"] += 1

        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        # Track conversations
        conv_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        self.conversations[conv_key] += 1

        # Track common ports
        self.stats["dst_ports"][dst_port] += 1

        # Detect suspicious patterns
        # SYN scan detection
        if tcp_layer.flags == "S":  # SYN flag only
            self.stats["syn_packets"][src_ip] += 1

        # Detect potential port scanning
        if self.stats["syn_packets"][src_ip] > 20:
            # Check if we already alerted for this IP
            if not any(
                a.get("source_ip") == src_ip and a.get("type") == "port_scan" for a in self.alerts
            ):
                self.alerts.append(
                    {
                        "type": "port_scan",
                        "severity": "medium",
                        "source_ip": src_ip,
                        "description": f"Potential port scan detected from {src_ip}",
                        "packets": self.stats["syn_packets"][src_ip],
                    }
                )

        # Analyze payload for HTTP
        if dst_port == 80 or src_port == 80:
            self._analyze_http(packet, src_ip, dst_ip)

        # DNS over TCP
        if dst_port == 53 or src_port == 53:
            self.stats["protocols"]["DNS"] += 1

    def _analyze_udp(self, packet, src_ip: str, dst_ip: str):
        """Analyze UDP packet"""
        self.stats["protocols"]["UDP"] += 1

        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

        # Track ports
        self.stats["dst_ports"][dst_port] += 1

        # DNS analysis
        if packet.haslayer(DNS):
            self._analyze_dns(packet, src_ip, dst_ip)

    def _analyze_http(self, packet, src_ip: str, dst_ip: str):
        """Analyze HTTP traffic"""
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load

        try:
            payload_str = payload.decode("utf-8", errors="ignore")

            # Check for suspicious patterns
            suspicious_patterns = [
                ("SQL Injection", ["union select", "or 1=1", "' or '1'='1"]),
                ("XSS", ["<script>", "javascript:", "onerror="]),
                ("Path Traversal", ["../../../", "..\\..\\..\\"]),
            ]

            for attack_type, patterns in suspicious_patterns:
                if any(pattern.lower() in payload_str.lower() for pattern in patterns):
                    self.alerts.append(
                        {
                            "type": attack_type.lower().replace(" ", "_"),
                            "severity": "high",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "description": f"{attack_type} pattern detected in HTTP traffic",
                            "payload_preview": payload_str[:100],
                        }
                    )

        except Exception:
            pass

    def _analyze_dns(self, packet, src_ip: str, dst_ip: str):
        """Analyze DNS traffic"""
        dns_layer = packet[DNS]

        # DNS Query
        if dns_layer.qr == 0 and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            self.stats["dns_queries"][query] += 1

            # Check for suspicious domains
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
            if any(query.endswith(tld) for tld in suspicious_tlds):
                self.alerts.append(
                    {
                        "type": "suspicious_domain",
                        "severity": "low",
                        "source_ip": src_ip,
                        "description": f"Query to suspicious TLD: {query}",
                        "domain": query,
                    }
                )

            # Check for potential DGA (Domain Generation Algorithm)
            if len(query) > 30 and "." not in query[:20]:
                self.alerts.append(
                    {
                        "type": "potential_dga",
                        "severity": "medium",
                        "source_ip": src_ip,
                        "description": f"Potential DGA domain: {query}",
                        "domain": query,
                    }
                )

    def _generate_statistics(self) -> Dict:
        """Generate statistics from analysis"""
        # Top source IPs
        src_ip_counter = Counter()
        dst_ip_counter = Counter()

        for conv, count in self.conversations.items():
            src = conv.split(" -> ")[0].split(":")[0]
            dst = conv.split(" -> ")[1].split(":")[0]
            src_ip_counter[src] += count
            dst_ip_counter[dst] += count

        # Top ports
        top_ports = [
            {"port": port, "count": count}
            for port, count in Counter(self.stats["dst_ports"]).most_common(10)
        ]

        # Top DNS queries
        top_dns = []
        if "dns_queries" in self.stats:
            top_dns = [
                {"domain": domain, "count": count}
                for domain, count in Counter(self.stats["dns_queries"]).most_common(10)
            ]

        # Top conversations
        top_conversations = [
            {"conversation": conv, "packets": count}
            for conv, count in sorted(self.conversations.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]
        ]

        return {
            "top_source_ips": [
                {"ip": ip, "packets": count} for ip, count in src_ip_counter.most_common(10)
            ],
            "top_destination_ips": [
                {"ip": ip, "packets": count} for ip, count in dst_ip_counter.most_common(10)
            ],
            "top_ports": top_ports,
            "top_dns_queries": top_dns,
            "top_conversations": top_conversations,
        }


def format_output_json(results: Dict) -> str:
    """Format results as JSON"""
    return json.dumps(results, indent=2, default=str)


def format_output_csv(results: Dict) -> str:
    """Format alerts as CSV"""
    lines = ["Type,Severity,Source_IP,Destination_IP,Description"]

    for alert in results.get("alerts", []):
        alert_type = alert.get("type", "")
        severity = alert.get("severity", "")
        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("destination_ip", "")
        description = alert.get("description", "").replace(",", ";")

        lines.append(f"{alert_type},{severity},{src_ip},{dst_ip},{description}")

    return "\n".join(lines)


def format_output_text(results: Dict) -> str:
    """Format results as plain text report"""
    lines = []

    # Header
    lines.append("=" * 70)
    lines.append("PCAP ANALYSIS REPORT")
    lines.append("=" * 70)

    metadata = results.get("metadata", {})
    summary = results.get("summary", {})

    lines.append(f"\nTotal Packets: {metadata.get('total_packets')}")
    lines.append(f"Total Bytes: {summary.get('total_bytes')}")
    lines.append(f"Unique Source IPs: {summary.get('unique_src_ips')}")
    lines.append(f"Unique Destination IPs: {summary.get('unique_dst_ips')}")
    lines.append(f"Total Alerts: {summary.get('total_alerts')}")
    lines.append(f"Analysis Date: {metadata.get('analysis_date')}")

    # Protocol distribution
    protocols = summary.get("protocols", {})
    if protocols:
        lines.append("\n" + "=" * 70)
        lines.append("PROTOCOL DISTRIBUTION")
        lines.append("=" * 70)
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {protocol}: {count} packets")

    # Statistics
    stats = results.get("statistics", {})

    if "top_source_ips" in stats and stats["top_source_ips"]:
        lines.append("\n" + "=" * 70)
        lines.append("TOP 10 SOURCE IPS")
        lines.append("=" * 70)
        for item in stats["top_source_ips"]:
            lines.append(f"  {item['ip']}: {item['packets']} packets")

    if "top_destination_ips" in stats and stats["top_destination_ips"]:
        lines.append("\n" + "=" * 70)
        lines.append("TOP 10 DESTINATION IPS")
        lines.append("=" * 70)
        for item in stats["top_destination_ips"]:
            lines.append(f"  {item['ip']}: {item['packets']} packets")

    if "top_ports" in stats and stats["top_ports"]:
        lines.append("\n" + "=" * 70)
        lines.append("TOP 10 DESTINATION PORTS")
        lines.append("=" * 70)
        for item in stats["top_ports"]:
            lines.append(f"  Port {item['port']}: {item['count']} packets")

    if "top_dns_queries" in stats and stats["top_dns_queries"]:
        lines.append("\n" + "=" * 70)
        lines.append("TOP 10 DNS QUERIES")
        lines.append("=" * 70)
        for item in stats["top_dns_queries"]:
            lines.append(f"  {item['domain']}: {item['count']} queries")

    # Alerts
    alerts = results.get("alerts", [])
    if alerts:
        lines.append("\n" + "=" * 70)
        lines.append(f"SECURITY ALERTS (showing first 20 of {len(alerts)})")
        lines.append("=" * 70)

        for i, alert in enumerate(alerts[:20], 1):
            lines.append(f"\n{i}. [{alert['severity'].upper()}] {alert['type']}")
            lines.append(f"   {alert['description']}")
            if "source_ip" in alert:
                lines.append(f"   Source: {alert['source_ip']}")
            if "destination_ip" in alert:
                lines.append(f"   Destination: {alert['destination_ip']}")

    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="PCAP Analyzer - Analyze network traffic from PCAP files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze PCAP file
  python analyzer.py capture.pcap

  # Export to text report
  python analyzer.py capture.pcap --format txt --output report.txt

  # Export alerts to CSV
  python analyzer.py capture.pcap --format csv --output alerts.csv

  # Verbose analysis
  python analyzer.py capture.pcap --verbose
        """,
    )

    parser.add_argument("pcap_file", help="Path to PCAP file to analyze")

    parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv", "txt"],
        default="json",
        help="Output format (default: json)",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    args = parse_args()

    # Check for scapy
    if not SCAPY_AVAILABLE:
        print("Error: scapy library not installed.", file=sys.stderr)
        print("Install with: pip install scapy", file=sys.stderr)
        sys.exit(1)

    # Initialize analyzer
    analyzer = PCAPAnalyzer(verbose=args.verbose)

    # Load PCAP
    if not analyzer.load_pcap(args.pcap_file):
        sys.exit(1)

    # Analyze
    results = analyzer.analyze()

    # Check for errors
    if "error" in results:
        print(f"Error: {results['error']}", file=sys.stderr)
        sys.exit(1)

    # Format output
    if args.format == "json":
        output = format_output_json(results)
    elif args.format == "csv":
        output = format_output_csv(results)
    elif args.format == "txt":
        output = format_output_text(results)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"\nOutput written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Print summary to stderr if verbose
    if args.verbose:
        metadata = results.get("metadata", {})
        summary = results.get("summary", {})
        print(f"\nAnalyzed {metadata.get('total_packets')} packets", file=sys.stderr)
        print(f"Found {summary.get('total_alerts')} alerts", file=sys.stderr)


if __name__ == "__main__":
    main()
