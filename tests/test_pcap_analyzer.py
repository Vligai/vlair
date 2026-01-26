#!/usr/bin/env python3
"""
Unit tests for PCAP Analyzer
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pcapAnalyzer.analyzer import PCAPAnalyzer, format_output_json, format_output_csv, format_output_text


class TestPCAPAnalyzer:
    """Test PCAP analyzer"""

    def test_init(self):
        """Test analyzer initialization"""
        analyzer = PCAPAnalyzer(verbose=False)

        assert analyzer.verbose is False
        assert analyzer.packets == []
        assert isinstance(analyzer.stats, dict)
        assert isinstance(analyzer.conversations, defaultdict)
        assert analyzer.alerts == []

    def test_load_pcap_file_not_found(self):
        """Test loading nonexistent PCAP file"""
        analyzer = PCAPAnalyzer()

        result = analyzer.load_pcap("/nonexistent/file.pcap")

        assert result is False

    @patch("pcapAnalyzer.analyzer.SCAPY_AVAILABLE", False)
    def test_load_pcap_no_scapy(self):
        """Test loading PCAP without scapy installed"""
        analyzer = PCAPAnalyzer()

        result = analyzer.load_pcap("test.pcap")

        assert result is False

    @patch("pcapAnalyzer.analyzer.rdpcap")
    @patch("pcapAnalyzer.analyzer.SCAPY_AVAILABLE", True)
    def test_load_pcap_success(self, mock_rdpcap):
        """Test successful PCAP loading"""
        mock_packets = [Mock(), Mock(), Mock()]
        mock_rdpcap.return_value = mock_packets

        # Create a temporary file
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_file = f.name

        try:
            analyzer = PCAPAnalyzer()
            result = analyzer.load_pcap(temp_file)

            assert result is True
            assert len(analyzer.packets) == 3
        finally:
            # Cleanup
            Path(temp_file).unlink()

    def test_analyze_no_packets(self):
        """Test analysis with no packets loaded"""
        analyzer = PCAPAnalyzer()

        result = analyzer.analyze()

        assert "error" in result
        assert "No packets" in result["error"]

    @patch("pcapAnalyzer.analyzer.IP")
    def test_analyze_packet_non_ip(self, mock_ip):
        """Test analyzing non-IP packet"""
        analyzer = PCAPAnalyzer()

        # Create mock packet without IP layer
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        mock_packet.__len__.return_value = 100

        analyzer._analyze_packet(mock_packet)

        assert analyzer.stats["total_bytes"] == 100
        assert analyzer.stats["protocols"]["non-ip"] == 1

    @patch("pcapAnalyzer.analyzer.TCP")
    @patch("pcapAnalyzer.analyzer.IP")
    def test_analyze_tcp_packet(self, mock_ip, mock_tcp):
        """Test analyzing TCP packet"""
        analyzer = PCAPAnalyzer()

        # Create mock TCP packet
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda layer: layer in [mock_ip, mock_tcp]
        mock_packet.__len__.return_value = 200

        mock_ip_layer = Mock()
        mock_ip_layer.src = "192.0.2.1"
        mock_ip_layer.dst = "198.51.100.25"
        mock_packet.__getitem__.side_effect = lambda layer: (
            mock_ip_layer if layer == mock_ip else Mock(sport=50000, dport=80, flags="S")
        )

        analyzer._analyze_packet(mock_packet)

        assert analyzer.stats["protocols"]["TCP"] == 1
        assert "192.0.2.1" in analyzer.stats["src_ips"]
        assert "198.51.100.25" in analyzer.stats["dst_ips"]

    @patch("pcapAnalyzer.analyzer.UDP")
    @patch("pcapAnalyzer.analyzer.IP")
    def test_analyze_udp_packet(self, mock_ip, mock_udp):
        """Test analyzing UDP packet"""
        analyzer = PCAPAnalyzer()

        # Create mock UDP packet
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda layer: layer in [mock_ip, mock_udp]
        mock_packet.__len__.return_value = 150

        mock_ip_layer = Mock()
        mock_ip_layer.src = "192.0.2.1"
        mock_ip_layer.dst = "8.8.8.8"
        mock_packet.__getitem__.side_effect = lambda layer: mock_ip_layer if layer == mock_ip else Mock(sport=50000, dport=53)

        analyzer._analyze_packet(mock_packet)

        assert analyzer.stats["protocols"]["UDP"] == 1

    @patch("pcapAnalyzer.analyzer.Raw")
    @patch("pcapAnalyzer.analyzer.TCP")
    def test_analyze_tcp_port_scan_detection(self, mock_tcp, mock_raw):
        """Test port scan detection"""
        analyzer = PCAPAnalyzer()

        # Simulate multiple SYN packets from same source
        for i in range(25):
            analyzer.stats["syn_packets"]["203.0.113.100"] += 1

        # Create mock packet
        mock_packet = MagicMock()

        mock_tcp_layer = Mock()
        mock_tcp_layer.sport = 50000
        mock_tcp_layer.dport = 22
        mock_tcp_layer.flags = "S"

        mock_packet.__getitem__.return_value = mock_tcp_layer
        mock_packet.haslayer.return_value = False  # No Raw layer

        analyzer._analyze_tcp(mock_packet, "203.0.113.100", "192.0.2.1")

        # Should detect port scan
        port_scan_alerts = [a for a in analyzer.alerts if a["type"] == "port_scan"]
        assert len(port_scan_alerts) > 0
        assert port_scan_alerts[0]["source_ip"] == "203.0.113.100"

    @patch("pcapAnalyzer.analyzer.Raw")
    def test_analyze_http_sql_injection(self, mock_raw_cls):
        """Test HTTP SQL injection detection"""
        analyzer = PCAPAnalyzer()

        # Create mock HTTP packet with SQL injection
        mock_packet = MagicMock()
        mock_raw = Mock()
        mock_raw.load = b"GET /search?q=' UNION SELECT password FROM users-- HTTP/1.1"

        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value = mock_raw

        analyzer._analyze_http(mock_packet, "203.0.113.100", "192.0.2.1")

        # Should detect SQL injection
        sql_alerts = [a for a in analyzer.alerts if "sql" in a["type"].lower()]
        assert len(sql_alerts) > 0
        assert sql_alerts[0]["severity"] == "high"

    @patch("pcapAnalyzer.analyzer.Raw")
    def test_analyze_http_xss(self, mock_raw_cls):
        """Test HTTP XSS detection"""
        analyzer = PCAPAnalyzer()

        # Create mock HTTP packet with XSS
        mock_packet = MagicMock()
        mock_raw = Mock()
        mock_raw.load = b"GET /comment?text=<script>alert('XSS')</script> HTTP/1.1"

        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value = mock_raw

        analyzer._analyze_http(mock_packet, "198.51.100.25", "192.0.2.1")

        # Should detect XSS
        xss_alerts = [a for a in analyzer.alerts if "xss" in a["type"].lower()]
        assert len(xss_alerts) > 0

    @patch("pcapAnalyzer.analyzer.Raw")
    def test_analyze_http_path_traversal(self, mock_raw_cls):
        """Test HTTP path traversal detection"""
        analyzer = PCAPAnalyzer()

        # Create mock HTTP packet with path traversal
        mock_packet = MagicMock()
        mock_raw = Mock()
        mock_raw.load = b"GET /../../../etc/passwd HTTP/1.1"

        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value = mock_raw

        analyzer._analyze_http(mock_packet, "203.0.113.100", "192.0.2.1")

        # Should detect path traversal
        path_alerts = [a for a in analyzer.alerts if "traversal" in a["type"].lower()]
        assert len(path_alerts) > 0

    @patch("pcapAnalyzer.analyzer.DNSQR")
    @patch("pcapAnalyzer.analyzer.DNS")
    def test_analyze_dns_suspicious_tld(self, mock_dns, mock_dnsqr):
        """Test DNS analysis for suspicious TLDs"""
        analyzer = PCAPAnalyzer()

        # Create mock DNS packet with suspicious TLD
        mock_packet = MagicMock()
        mock_dns_layer = Mock()
        mock_dns_layer.qr = 0  # Query

        mock_dnsqr_layer = Mock()
        mock_dnsqr_layer.qname = b"malicious-site.tk."

        mock_packet.haslayer.side_effect = lambda layer: True
        mock_packet.__getitem__.side_effect = lambda layer: (mock_dns_layer if layer == mock_dns else mock_dnsqr_layer)

        analyzer._analyze_dns(mock_packet, "192.0.2.1", "8.8.8.8")

        # Should detect suspicious domain
        suspicious_alerts = [a for a in analyzer.alerts if a["type"] == "suspicious_domain"]
        assert len(suspicious_alerts) > 0
        assert ".tk" in suspicious_alerts[0]["domain"]

    @patch("pcapAnalyzer.analyzer.DNSQR")
    @patch("pcapAnalyzer.analyzer.DNS")
    def test_analyze_dns_dga(self, mock_dns, mock_dnsqr):
        """Test DNS analysis for potential DGA"""
        analyzer = PCAPAnalyzer()

        # Create mock DNS packet with DGA-like domain
        mock_packet = MagicMock()
        mock_dns_layer = Mock()
        mock_dns_layer.qr = 0  # Query

        # Long, random-looking domain
        mock_dnsqr_layer = Mock()
        mock_dnsqr_layer.qname = b"asdfjklasdfjklqweriuqweriuzxcvzxcv.com."

        mock_packet.haslayer.side_effect = lambda layer: True
        mock_packet.__getitem__.side_effect = lambda layer: (mock_dns_layer if layer == mock_dns else mock_dnsqr_layer)

        analyzer._analyze_dns(mock_packet, "192.0.2.1", "8.8.8.8")

        # Should detect potential DGA
        dga_alerts = [a for a in analyzer.alerts if a["type"] == "potential_dga"]
        assert len(dga_alerts) > 0

    def test_generate_statistics(self):
        """Test statistics generation"""
        analyzer = PCAPAnalyzer()

        # Add some conversations
        analyzer.conversations["192.0.2.1:50000 -> 198.51.100.25:80"] = 10
        analyzer.conversations["192.0.2.1:50001 -> 198.51.100.25:443"] = 5
        analyzer.conversations["203.0.113.100:50000 -> 8.8.8.8:53"] = 3

        # Add some port stats
        analyzer.stats["dst_ports"][80] = 10
        analyzer.stats["dst_ports"][443] = 5
        analyzer.stats["dst_ports"][53] = 3

        # Add some DNS queries
        analyzer.stats["dns_queries"]["example.com"] = 5
        analyzer.stats["dns_queries"]["google.com"] = 3

        stats = analyzer._generate_statistics()

        assert "top_source_ips" in stats
        assert "top_destination_ips" in stats
        assert "top_ports" in stats
        assert "top_dns_queries" in stats
        assert "top_conversations" in stats

        # Check if sorted by count
        if len(stats["top_ports"]) > 1:
            assert stats["top_ports"][0]["count"] >= stats["top_ports"][1]["count"]


class TestFormatOutput:
    """Test output formatting"""

    def test_format_output_json(self):
        """Test JSON output formatting"""
        results = {"metadata": {"total_packets": 100}, "summary": {"total_alerts": 5}, "alerts": []}

        output = format_output_json(results)

        assert "total_packets" in output
        assert "100" in output

        # Should be valid JSON
        import json

        parsed = json.loads(output)
        assert parsed["metadata"]["total_packets"] == 100

    def test_format_output_csv(self):
        """Test CSV output formatting"""
        results = {
            "alerts": [
                {
                    "type": "port_scan",
                    "severity": "medium",
                    "source_ip": "203.0.113.100",
                    "destination_ip": "192.0.2.1",
                    "description": "Potential port scan detected",
                },
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "source_ip": "198.51.100.25",
                    "destination_ip": "192.0.2.50",
                    "description": "SQL injection pattern detected",
                },
            ]
        }

        output = format_output_csv(results)

        lines = output.split("\n")
        assert "Type,Severity,Source_IP" in lines[0]
        assert "port_scan" in lines[1]
        assert "sql_injection" in lines[2]

    def test_format_output_text(self):
        """Test text output formatting"""
        results = {
            "metadata": {"total_packets": 1000, "analysis_date": "2025-11-18T10:00:00"},
            "summary": {
                "total_bytes": 500000,
                "unique_src_ips": 10,
                "unique_dst_ips": 5,
                "total_alerts": 3,
                "protocols": {"TCP": 800, "UDP": 150, "non-ip": 50},
            },
            "statistics": {
                "top_source_ips": [{"ip": "192.0.2.1", "packets": 500}],
                "top_destination_ips": [{"ip": "198.51.100.25", "packets": 300}],
                "top_ports": [{"port": 80, "count": 400}, {"port": 443, "count": 200}],
                "top_dns_queries": [{"domain": "example.com", "count": 10}],
            },
            "alerts": [
                {
                    "type": "port_scan",
                    "severity": "medium",
                    "source_ip": "203.0.113.100",
                    "description": "Potential port scan detected",
                }
            ],
        }

        output = format_output_text(results)

        assert "PCAP ANALYSIS REPORT" in output
        assert "Total Packets: 1000" in output
        assert "PROTOCOL DISTRIBUTION" in output
        assert "TCP: 800" in output
        assert "TOP 10 SOURCE IPS" in output
        assert "192.0.2.1" in output
        assert "TOP 10 DESTINATION PORTS" in output
        assert "Port 80" in output
        assert "SECURITY ALERTS" in output
        assert "port_scan" in output


class TestIntegration:
    """Integration tests"""

    def test_full_analysis_workflow(self):
        """Test complete analysis workflow with mocked packets"""
        analyzer = PCAPAnalyzer()

        # Create some mock packets
        mock_packets = []
        for i in range(5):
            mock_packet = MagicMock()
            mock_packet.haslayer.return_value = False
            mock_packet.__len__.return_value = 100
            mock_packets.append(mock_packet)

        analyzer.packets = mock_packets

        # Run analysis
        result = analyzer.analyze()

        assert "error" not in result
        assert "metadata" in result
        assert result["metadata"]["total_packets"] == 5
        assert "summary" in result
        assert "statistics" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
