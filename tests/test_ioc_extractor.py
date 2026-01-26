#!/usr/bin/env python3
"""
Unit tests for IOC Extractor
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from iocExtractor.extractor import IOCExtractor


class TestIOCExtractor:
    """Test IOC Extractor functionality"""

    def test_extract_ipv4_basic(self):
        """Test basic IPv4 extraction"""
        extractor = IOCExtractor()
        text = "Malicious traffic from 192.0.2.1 and 198.51.100.25 detected"
        result = extractor.extract_from_text(text, types=["ip"])

        assert "192.0.2.1" in result["ips"]
        assert "198.51.100.25" in result["ips"]
        assert len(result["ips"]) == 2

    def test_extract_ipv4_invalid(self):
        """Test that invalid IPs are not extracted"""
        extractor = IOCExtractor()
        text = "Invalid IP: 999.999.999.999 and 192.0.2.256"
        result = extractor.extract_from_text(text, types=["ip"])

        assert len(result["ips"]) == 0

    def test_extract_domain(self):
        """Test domain extraction"""
        extractor = IOCExtractor()
        text = "Visit malicious.example.com and badactor.net"
        result = extractor.extract_from_text(text, types=["domain"])

        assert "malicious.example.com" in result["domains"]
        assert "badactor.net" in result["domains"]

    def test_extract_defanged_domain(self):
        """Test defanged domain extraction with refang"""
        extractor = IOCExtractor(refang=True)
        text = "Visit malicious[.]example[.]com"
        result = extractor.extract_from_text(text, types=["domain"])

        assert "malicious.example.com" in result["domains"]

    def test_extract_defanged_ip(self):
        """Test defanged IP extraction with refang"""
        extractor = IOCExtractor(refang=True)
        text = "IP address: 192[.]0[.]2[.]1"
        result = extractor.extract_from_text(text, types=["ip"])

        assert "192.0.2.1" in result["ips"]

    def test_extract_url(self):
        """Test URL extraction"""
        extractor = IOCExtractor()
        text = "Download from http://malicious.com/payload.exe"
        result = extractor.extract_from_text(text, types=["url"])

        assert "http://malicious.com/payload.exe" in result["urls"]

    def test_extract_defanged_url(self):
        """Test defanged URL extraction"""
        extractor = IOCExtractor(refang=True)
        text = "Visit hxxp://malicious[.]com/payload"
        result = extractor.extract_from_text(text, types=["url"])

        assert "http://malicious.com/payload" in result["urls"]

    def test_extract_email(self):
        """Test email extraction"""
        extractor = IOCExtractor()
        text = "Contact attacker@malicious.com or admin@badactor.net"
        result = extractor.extract_from_text(text, types=["email"])

        assert "attacker@malicious.com" in result["emails"]
        assert "admin@badactor.net" in result["emails"]

    def test_extract_defanged_email(self):
        """Test defanged email extraction"""
        extractor = IOCExtractor(refang=True)
        text = "Email: attacker[@]malicious[.]com"
        result = extractor.extract_from_text(text, types=["email"])

        assert "attacker@malicious.com" in result["emails"]

    def test_extract_md5(self):
        """Test MD5 hash extraction"""
        extractor = IOCExtractor()
        text = "MD5: 5d41402abc4b2a76b9719d911017c592"
        result = extractor.extract_from_text(text, types=["hash"])

        assert "5d41402abc4b2a76b9719d911017c592" in result["hashes"]["md5"]

    def test_extract_sha1(self):
        """Test SHA1 hash extraction"""
        extractor = IOCExtractor()
        text = "SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        result = extractor.extract_from_text(text, types=["hash"])

        assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in result["hashes"]["sha1"]

    def test_extract_sha256(self):
        """Test SHA256 hash extraction"""
        extractor = IOCExtractor()
        text = "SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        result = extractor.extract_from_text(text, types=["hash"])

        assert "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" in result["hashes"]["sha256"]

    def test_extract_cve(self):
        """Test CVE extraction"""
        extractor = IOCExtractor()
        text = "Exploits CVE-2024-1234 and CVE-2023-5678"
        result = extractor.extract_from_text(text, types=["cve"])

        assert "CVE-2024-1234" in result["cves"]
        assert "CVE-2023-5678" in result["cves"]

    def test_exclude_private_ips(self):
        """Test private IP exclusion"""
        extractor = IOCExtractor(exclude_private_ips=True)
        text = "Server at 192.168.1.1, 10.0.0.1, and 8.8.8.8"
        result = extractor.extract_from_text(text, types=["ip"])

        assert "192.168.1.1" not in result["ips"]
        assert "10.0.0.1" not in result["ips"]
        assert "8.8.8.8" in result["ips"]

    def test_defang_output(self):
        """Test defanging IOCs in output"""
        extractor = IOCExtractor(defang=True)
        text = "IP: 192.0.2.1 Domain: malicious.com Email: bad@evil.net"
        result = extractor.extract_from_text(text)

        assert "192[.]0[.]2[.]1" in result["ips"]
        assert "malicious[.]com" in result["domains"]
        assert "bad[@]evil[.]net" in result["emails"]

    def test_deduplication(self):
        """Test that duplicate IOCs are removed"""
        extractor = IOCExtractor()
        text = "IP 192.0.2.1 appeared, and 192.0.2.1 appeared again"
        result = extractor.extract_from_text(text, types=["ip"])

        assert len(result["ips"]) == 1
        assert "192.0.2.1" in result["ips"]

    def test_extract_from_file(self):
        """Test extracting from file"""
        extractor = IOCExtractor()
        test_file = Path(__file__).parent / "test_data" / "ioc_samples" / "threat_report.txt"

        result = extractor.extract_from_file(str(test_file))

        # Should find various IOCs from the threat report
        assert len(result["ips"]) > 0
        assert len(result["domains"]) > 0
        assert len(result["emails"]) > 0
        assert len(result["hashes"]["md5"]) > 0

    def test_empty_input(self):
        """Test with empty input"""
        extractor = IOCExtractor()
        result = extractor.extract_from_text("", types=["all"])

        assert len(result["ips"]) == 0
        assert len(result["domains"]) == 0
        assert len(result["urls"]) == 0

    def test_no_iocs(self):
        """Test with text containing no IOCs"""
        extractor = IOCExtractor()
        text = "This is just plain text with no indicators"
        result = extractor.extract_from_text(text, types=["all"])

        assert len(result["ips"]) == 0
        assert len(result["domains"]) == 0
        assert len(result["urls"]) == 0

    def test_mixed_ioc_types(self):
        """Test extracting multiple IOC types at once"""
        extractor = IOCExtractor()
        text = """
        IP: 192.0.2.1
        Domain: malicious.com
        Email: bad@evil.net
        Hash: 5d41402abc4b2a76b9719d911017c592
        CVE: CVE-2024-1234
        """
        result = extractor.extract_from_text(text, types=["all"])

        assert len(result["ips"]) > 0
        assert len(result["domains"]) > 0
        assert len(result["emails"]) > 0
        assert len(result["hashes"]["md5"]) > 0
        assert len(result["cves"]) > 0

    def test_get_summary(self):
        """Test summary generation"""
        extractor = IOCExtractor()
        text = "IP: 192.0.2.1, Domain: evil.com, Email: bad@attacker.org"
        result = extractor.extract_from_text(text)
        summary = extractor.get_summary(result)

        assert summary["ips"] == 1
        assert summary["domains"] >= 1  # May extract domains from email too
        assert summary["emails"] == 1
        assert summary["total_iocs"] >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
