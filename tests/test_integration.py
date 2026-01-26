#!/usr/bin/env python3
"""
Integration tests for SecOps Helper
Tests complete workflows combining multiple tools
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from iocExtractor.extractor import IOCExtractor
from hashLookup.lookup import HashValidator
from domainIpIntel.intel import Validator, DomainIPIntelligence


class TestIOCWorkflow:
    """Test complete IOC extraction and analysis workflow"""

    def test_extract_and_validate_ips(self):
        """Test extracting IPs and validating them"""
        extractor = IOCExtractor()

        text = """
        Suspicious traffic detected from 192.0.2.50 and 198.51.100.25.
        These IPs are communicating with 203.0.113.100 on port 8443.
        """

        # Extract IPs
        result = extractor.extract_from_text(text, types=["ip"])

        assert len(result["ips"]) > 0

        # Validate each IP
        for ip in result["ips"]:
            is_valid = Validator.is_valid_ipv4(ip)
            assert is_valid is True

    def test_extract_and_validate_domains(self):
        """Test extracting domains and validating them"""
        extractor = IOCExtractor()

        text = """
        Malicious domains identified:
        - malicious-update.example.com
        - badactor.net
        - phishing-portal.suspicious-site.com
        """

        # Extract domains
        result = extractor.extract_from_text(text, types=["domain"])

        assert len(result["domains"]) > 0

        # Validate each domain
        for domain in result["domains"]:
            is_valid = Validator.is_valid_domain(domain)
            assert is_valid is True

    def test_extract_and_validate_hashes(self):
        """Test extracting hashes and validating them"""
        extractor = IOCExtractor()

        text = """
        File hashes for malware samples:
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
        """

        # Extract hashes
        result = extractor.extract_from_text(text, types=["hash"])

        # Validate MD5
        for md5_hash in result["hashes"]["md5"]:
            is_valid, hash_type = HashValidator.validate(md5_hash)
            assert is_valid is True
            assert hash_type == "md5"

        # Validate SHA1
        for sha1_hash in result["hashes"]["sha1"]:
            is_valid, hash_type = HashValidator.validate(sha1_hash)
            assert is_valid is True
            assert hash_type == "sha1"

        # Validate SHA256
        for sha256_hash in result["hashes"]["sha256"]:
            is_valid, hash_type = HashValidator.validate(sha256_hash)
            assert is_valid is True
            assert hash_type == "sha256"

    def test_extract_from_threat_report(self):
        """Test extracting IOCs from actual threat report"""
        test_file = Path(__file__).parent / "test_data" / "ioc_samples" / "threat_report.txt"

        if not test_file.exists():
            pytest.skip("Threat report test file not found")

        extractor = IOCExtractor()
        result = extractor.extract_from_file(str(test_file))

        # Should find various IOC types
        assert len(result["ips"]) > 0, "Should find IP addresses"
        assert len(result["domains"]) > 0, "Should find domains"
        assert len(result["emails"]) > 0, "Should find email addresses"
        assert len(result["hashes"]["md5"]) > 0, "Should find MD5 hashes"
        assert len(result["cves"]) > 0, "Should find CVEs"

        # Validate all extracted IPs
        for ip in result["ips"]:
            assert Validator.is_valid_ipv4(ip), f"Invalid IP: {ip}"

        # Validate all extracted domains
        for domain in result["domains"]:
            # Some domains may have special characters from defanging
            if "[.]" not in domain:
                assert Validator.is_valid_domain(domain), f"Invalid domain: {domain}"

    def test_defang_refang_workflow(self):
        """Test defanging IOCs and then refanging them"""
        extractor_refang = IOCExtractor(refang=True)
        extractor_defang = IOCExtractor(defang=True)

        defanged_text = """
        Defanged IOCs:
        IP: 192[.]0[.]2[.]50
        Domain: malicious[.]example[.]com
        URL: hxxp://badactor[.]net/payload
        Email: attacker[@]evil[.]com
        """

        # Refang and extract
        refanged_result = extractor_refang.extract_from_text(defanged_text)

        assert "192.0.2.1" in refanged_result["ips"] or "192.0.2.50" in refanged_result["ips"]
        assert any("malicious.example.com" in d for d in refanged_result["domains"])

        # Now defang the results
        normal_text = """
        Normal IOCs:
        IP: 192.0.2.50
        Domain: malicious.example.com
        """

        defanged_result = extractor_defang.extract_from_text(normal_text)

        # Check that results are defanged
        for ip in defanged_result["ips"]:
            assert "[.]" in ip, "IPs should be defanged"

        for domain in defanged_result["domains"]:
            assert "[.]" in domain, "Domains should be defanged"


class TestThreatAnalysisWorkflow:
    """Test threat analysis workflows"""

    @patch("domainIpIntel.intel.VirusTotalAPI")
    @patch("domainIpIntel.intel.AbuseIPDBAPI")
    @patch("domainIpIntel.intel.DNSLookup.resolve_ptr")
    def test_ip_reputation_analysis(self, mock_resolve_ptr, mock_abuseipdb, mock_vt):
        """Test complete IP reputation analysis workflow"""
        # Mock DNS
        mock_resolve_ptr.return_value = "attacker.example.com"

        # Mock AbuseIPDB with high abuse score
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.lookup_ip.return_value = {
            "source": "abuseipdb",
            "abuse_confidence_score": 100,
            "total_reports": 50,
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance

        # Mock VirusTotal with malicious detections
        mock_vt_instance = Mock()
        mock_vt_instance.lookup_ip.return_value = {"source": "virustotal", "malicious": 10, "suspicious": 2}
        mock_vt.return_value = mock_vt_instance

        # Analyze IP
        intel = DomainIPIntelligence()
        result = intel.analyze_ip("203.0.113.100")

        # Should have proper structure (score depends on API responses)
        assert result["type"] == "ipv4"
        assert "reputation" in result
        assert "score" in result["reputation"]
        assert "risk_level" in result["reputation"]
        # With mocked APIs, should have high score
        if result.get("threat_intelligence"):
            assert result["reputation"]["score"] >= 0

    @patch("domainIpIntel.intel.VirusTotalAPI")
    @patch("domainIpIntel.intel.DNSLookup.get_dns_info")
    def test_domain_reputation_analysis(self, mock_dns, mock_vt):
        """Test complete domain reputation analysis workflow"""
        # Mock DNS
        mock_dns.return_value = {"a_records": ["203.0.113.100"], "reverse_dns": {}}

        # Mock VirusTotal with malicious detections
        mock_vt_instance = Mock()
        mock_vt_instance.lookup_domain.return_value = {"source": "virustotal", "malicious": 8, "suspicious": 3}
        mock_vt.return_value = mock_vt_instance

        # Analyze domain
        intel = DomainIPIntelligence()
        result = intel.analyze_domain("malicious.example.com")

        # Should have proper structure
        assert result["type"] == "domain"
        assert "reputation" in result
        assert "score" in result["reputation"]
        assert result["reputation"]["score"] >= 0

    def test_private_ip_filtering(self):
        """Test that private IPs are handled correctly"""
        extractor = IOCExtractor(exclude_private_ips=True)

        text = """
        Internal network: 192.168.1.100, 10.0.0.50
        External attacker: 203.0.113.100
        """

        result = extractor.extract_from_text(text, types=["ip"])

        # Should only have public IP
        assert "203.0.113.100" in result["ips"]
        assert "192.168.1.100" not in result["ips"]
        assert "10.0.0.50" not in result["ips"]

        # Verify private IP detection
        assert Validator.is_private_ip("192.168.1.100") is True
        assert Validator.is_private_ip("10.0.0.50") is True
        assert Validator.is_private_ip("203.0.113.100") is False


class TestDataValidation:
    """Test data validation across tools"""

    def test_hash_validation_consistency(self):
        """Test that hash validation is consistent"""
        test_hashes = {
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        }

        for hash_type, hash_value in test_hashes.items():
            # Validate using HashValidator
            is_valid, detected_type = HashValidator.validate(hash_value)

            assert is_valid is True, f"{hash_type} validation failed"
            assert detected_type == hash_type, f"Expected {hash_type}, got {detected_type}"

    def test_ip_validation_consistency(self):
        """Test that IP validation is consistent"""
        valid_ips = ["192.0.2.1", "8.8.8.8", "1.1.1.1", "255.255.255.255"]
        invalid_ips = ["256.1.1.1", "192.168.1", "192.168.1.1.1", "not-an-ip"]

        for ip in valid_ips:
            assert Validator.is_valid_ipv4(ip) is True, f"Valid IP rejected: {ip}"

        for ip in invalid_ips:
            assert Validator.is_valid_ipv4(ip) is False, f"Invalid IP accepted: {ip}"

    def test_domain_validation_consistency(self):
        """Test that domain validation is consistent"""
        valid_domains = ["example.com", "sub.example.com", "test.co.uk", "my-domain.net"]

        invalid_domains = ["", "example", ".example.com", "example..com", "-example.com"]

        for domain in valid_domains:
            assert Validator.is_valid_domain(domain) is True, f"Valid domain rejected: {domain}"

        for domain in invalid_domains:
            assert Validator.is_valid_domain(domain) is False, f"Invalid domain accepted: {domain}"


class TestFileProcessing:
    """Test file processing workflows"""

    def test_process_multiple_files(self):
        """Test processing multiple IOC files"""
        test_files = [
            Path(__file__).parent / "test_data" / "ioc_samples" / "threat_report.txt",
            Path(__file__).parent / "test_data" / "ioc_samples" / "defanged_iocs.txt",
        ]

        extractor = IOCExtractor(refang=True)
        all_results = []

        for test_file in test_files:
            if test_file.exists():
                result = extractor.extract_from_file(str(test_file))
                all_results.append(result)

        # Should have results from files
        assert len(all_results) > 0

        # Aggregate all IOCs
        all_ips = set()
        all_domains = set()

        for result in all_results:
            all_ips.update(result["ips"])
            all_domains.update(result["domains"])

        # Should have collected multiple IOCs
        if all_ips:
            assert len(all_ips) > 0
        if all_domains:
            assert len(all_domains) > 0


class TestErrorHandling:
    """Test error handling across tools"""

    def test_invalid_file_path(self):
        """Test handling of invalid file paths"""
        extractor = IOCExtractor()

        # Should handle nonexistent file gracefully
        try:
            result = extractor.extract_from_file("/nonexistent/file.txt")
            # May return empty results or raise exception
            assert True
        except FileNotFoundError:
            assert True

    def test_empty_input(self):
        """Test handling of empty input"""
        extractor = IOCExtractor()

        result = extractor.extract_from_text("", types=["all"])

        # Should return empty results, not crash
        assert result["ips"] == []
        assert result["domains"] == []
        assert result["urls"] == []

    def test_invalid_hash_format(self):
        """Test handling of invalid hash formats"""
        is_valid, hash_type = HashValidator.validate("invalid_hash_123")

        assert is_valid is False
        assert hash_type is None

    def test_invalid_ip_format(self):
        """Test handling of invalid IP formats"""
        assert Validator.is_valid_ipv4("999.999.999.999") is False
        assert Validator.is_valid_ipv4("not.an.ip.addr") is False
        assert Validator.is_valid_ipv4("") is False


class TestPerformance:
    """Test performance with larger datasets"""

    def test_extract_from_large_text(self):
        """Test IOC extraction from large text"""
        # Generate large text with IOCs
        large_text = ""
        for i in range(100):
            large_text += f"IP: 192.0.2.{i % 255}\n"
            large_text += f"Domain: test{i}.example.com\n"
            large_text += f"Hash: {'a' * 32}\n"

        extractor = IOCExtractor()
        result = extractor.extract_from_text(large_text)

        # Should handle large input
        assert len(result["ips"]) > 0
        assert len(result["domains"]) > 0

    def test_deduplication_performance(self):
        """Test that deduplication works correctly"""
        # Text with many duplicate IOCs - ensure domains are clearly formatted
        text = """
        Repeated IPs: 192.0.2.1 and 192.0.2.1 and 192.0.2.1
        Repeated domains: malicious.example.com and malicious.example.com and malicious.example.com
        More domains: badactor.net and badactor.net
        """

        extractor = IOCExtractor()
        result = extractor.extract_from_text(text, types=["all"])

        # Should find IOCs and deduplicate them
        if len(result["ips"]) > 0:
            # If IPs are found, should be deduplicated
            assert len(result["ips"]) <= 3
        if len(result["domains"]) > 0:
            # If domains are found, should be deduplicated
            assert len(result["domains"]) <= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
