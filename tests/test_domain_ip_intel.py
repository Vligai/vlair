#!/usr/bin/env python3
"""
Unit tests for Domain/IP Intelligence
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from domainIpIntel.intel import Validator, DNSLookup, RiskScorer, AbuseIPDBAPI, VirusTotalAPI, DomainIPIntelligence


class TestValidator:
    """Test input validation"""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses"""
        assert Validator.is_valid_ipv4("192.0.2.1") is True
        assert Validator.is_valid_ipv4("8.8.8.8") is True
        assert Validator.is_valid_ipv4("255.255.255.255") is True
        assert Validator.is_valid_ipv4("0.0.0.0") is True

    def test_invalid_ipv4_format(self):
        """Test invalid IPv4 formats"""
        assert Validator.is_valid_ipv4("256.1.1.1") is False
        assert Validator.is_valid_ipv4("192.168.1") is False
        assert Validator.is_valid_ipv4("192.168.1.1.1") is False
        assert Validator.is_valid_ipv4("invalid") is False
        assert Validator.is_valid_ipv4("192.168.-1.1") is False

    def test_valid_domain(self):
        """Test valid domain names"""
        assert Validator.is_valid_domain("example.com") is True
        assert Validator.is_valid_domain("sub.example.com") is True
        assert Validator.is_valid_domain("test.co.uk") is True
        assert Validator.is_valid_domain("my-domain.net") is True

    def test_invalid_domain(self):
        """Test invalid domain names"""
        assert Validator.is_valid_domain("") is False
        assert Validator.is_valid_domain("example") is False
        assert Validator.is_valid_domain(".example.com") is False
        assert Validator.is_valid_domain("example..com") is False
        assert Validator.is_valid_domain("example-.com") is False
        assert Validator.is_valid_domain("-example.com") is False
        # Domain too long (>253 chars)
        assert Validator.is_valid_domain("a" * 254 + ".com") is False

    def test_private_ip_detection(self):
        """Test private IP address detection"""
        # 10.0.0.0/8
        assert Validator.is_private_ip("10.0.0.1") is True
        assert Validator.is_private_ip("10.255.255.255") is True

        # 172.16.0.0/12
        assert Validator.is_private_ip("172.16.0.1") is True
        assert Validator.is_private_ip("172.31.255.255") is True
        assert Validator.is_private_ip("172.15.0.1") is False
        assert Validator.is_private_ip("172.32.0.1") is False

        # 192.168.0.0/16
        assert Validator.is_private_ip("192.168.1.1") is True
        assert Validator.is_private_ip("192.168.255.255") is True

        # Loopback
        assert Validator.is_private_ip("127.0.0.1") is True

        # Link-local
        assert Validator.is_private_ip("169.254.1.1") is True

        # Public IPs
        assert Validator.is_private_ip("8.8.8.8") is False
        assert Validator.is_private_ip("1.1.1.1") is False


class TestDNSLookup:
    """Test DNS resolution"""

    @patch("socket.gethostbyname_ex")
    def test_resolve_a(self, mock_gethostbyname):
        """Test A record resolution"""
        mock_gethostbyname.return_value = ("example.com", [], ["93.184.216.34"])

        result = DNSLookup.resolve_a("example.com")
        assert "93.184.216.34" in result

    @patch("socket.gethostbyname_ex")
    def test_resolve_a_failure(self, mock_gethostbyname):
        """Test A record resolution failure"""
        mock_gethostbyname.side_effect = Exception("DNS resolution failed")

        result = DNSLookup.resolve_a("nonexistent.example.com")
        assert result == []

    @patch("socket.gethostbyaddr")
    def test_resolve_ptr(self, mock_gethostbyaddr):
        """Test reverse DNS lookup"""
        mock_gethostbyaddr.return_value = ("example.com", [], ["8.8.8.8"])

        result = DNSLookup.resolve_ptr("8.8.8.8")
        assert result == "example.com"

    @patch("socket.gethostbyaddr")
    def test_resolve_ptr_failure(self, mock_gethostbyaddr):
        """Test reverse DNS lookup failure"""
        mock_gethostbyaddr.side_effect = Exception("PTR lookup failed")

        result = DNSLookup.resolve_ptr("192.0.2.1")
        assert result is None

    @patch("domainIpIntel.intel.DNSLookup.resolve_ptr")
    @patch("domainIpIntel.intel.DNSLookup.resolve_a")
    def test_get_dns_info(self, mock_resolve_a, mock_resolve_ptr):
        """Test comprehensive DNS info retrieval"""
        mock_resolve_a.return_value = ["93.184.216.34"]
        mock_resolve_ptr.return_value = "example.com"

        result = DNSLookup.get_dns_info("example.com")

        assert "93.184.216.34" in result["a_records"]
        assert result["reverse_dns"]["93.184.216.34"] == "example.com"


class TestRiskScorer:
    """Test risk scoring algorithms"""

    def test_calculate_ip_score_clean(self):
        """Test IP risk score for clean IP"""
        intel_data = {"threat_intelligence": {"abuseipdb": {"abuse_confidence_score": 0}, "virustotal": {"malicious": 0}}}
        score = RiskScorer.calculate_ip_score(intel_data)
        assert score == 0

    def test_calculate_ip_score_abuseipdb(self):
        """Test IP risk score with AbuseIPDB data"""
        intel_data = {"threat_intelligence": {"abuseipdb": {"abuse_confidence_score": 80}, "virustotal": {"malicious": 0}}}
        score = RiskScorer.calculate_ip_score(intel_data)
        assert score == 40  # 80 * 0.5 = 40

    def test_calculate_ip_score_virustotal(self):
        """Test IP risk score with VirusTotal data"""
        intel_data = {"threat_intelligence": {"abuseipdb": {"abuse_confidence_score": 0}, "virustotal": {"malicious": 5}}}
        score = RiskScorer.calculate_ip_score(intel_data)
        assert score == 25  # 5 * 5 = 25

    def test_calculate_ip_score_combined(self):
        """Test IP risk score with combined sources"""
        intel_data = {"threat_intelligence": {"abuseipdb": {"abuse_confidence_score": 100}, "virustotal": {"malicious": 10}}}
        score = RiskScorer.calculate_ip_score(intel_data)
        # 100 * 0.5 + min(10 * 5, 40) = 50 + 40 = 90
        assert score == 90

    def test_calculate_ip_score_max_cap(self):
        """Test IP risk score capping at 100"""
        intel_data = {"threat_intelligence": {"abuseipdb": {"abuse_confidence_score": 100}, "virustotal": {"malicious": 20}}}
        score = RiskScorer.calculate_ip_score(intel_data)
        # VT is capped at 40, so max is 100*0.5 + 40 = 90
        assert score == 90

    def test_calculate_domain_score_clean(self):
        """Test domain risk score for clean domain"""
        intel_data = {"threat_intelligence": {"virustotal": {"malicious": 0, "suspicious": 0}}}
        score = RiskScorer.calculate_domain_score(intel_data)
        assert score == 0

    def test_calculate_domain_score_malicious(self):
        """Test domain risk score with malicious detections"""
        intel_data = {"threat_intelligence": {"virustotal": {"malicious": 10, "suspicious": 5}}}
        score = RiskScorer.calculate_domain_score(intel_data)
        # min(10 * 5, 50) + min(5 * 2, 20) = 50 + 10 = 60
        assert score == 60

    def test_classify_risk_critical(self):
        """Test critical risk classification"""
        assert RiskScorer.classify_risk(85) == "Critical"
        assert RiskScorer.classify_risk(100) == "Critical"

    def test_classify_risk_high(self):
        """Test high risk classification"""
        assert RiskScorer.classify_risk(60) == "High"
        assert RiskScorer.classify_risk(75) == "High"

    def test_classify_risk_medium(self):
        """Test medium risk classification"""
        assert RiskScorer.classify_risk(40) == "Medium"
        assert RiskScorer.classify_risk(55) == "Medium"

    def test_classify_risk_low(self):
        """Test low risk classification"""
        assert RiskScorer.classify_risk(20) == "Low"
        assert RiskScorer.classify_risk(35) == "Low"

    def test_classify_risk_clean(self):
        """Test clean risk classification"""
        assert RiskScorer.classify_risk(0) == "Clean"
        assert RiskScorer.classify_risk(15) == "Clean"


class TestAbuseIPDBAPI:
    """Test AbuseIPDB API integration"""

    def test_init_with_key(self):
        """Test API initialization with key"""
        api = AbuseIPDBAPI("test_key")
        assert api.api_key == "test_key"

    @patch("requests.get")
    def test_lookup_ip_success(self, mock_get):
        """Test successful IP lookup"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 50,
                "numDistinctUsers": 10,
                "lastReportedAt": "2025-11-18T10:00:00Z",
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example ISP",
                "domain": "example.com",
                "isWhitelisted": False,
            }
        }
        mock_get.return_value = mock_response

        api = AbuseIPDBAPI("test_key")
        result = api.lookup_ip("8.8.8.8")

        assert result["source"] == "abuseipdb"
        assert result["abuse_confidence_score"] == 85
        assert result["total_reports"] == 50
        assert result["country_code"] == "US"

    @patch("requests.get")
    def test_lookup_ip_error(self, mock_get):
        """Test IP lookup with error"""
        mock_get.side_effect = Exception("Network error")

        api = AbuseIPDBAPI("test_key")
        result = api.lookup_ip("8.8.8.8")

        assert result["source"] == "abuseipdb"
        assert "error" in result


class TestVirusTotalAPI:
    """Test VirusTotal API integration"""

    def test_init_with_key(self):
        """Test API initialization with key"""
        api = VirusTotalAPI("test_key")
        assert api.api_key == "test_key"

    @patch("requests.get")
    def test_lookup_ip_success(self, mock_get):
        """Test successful IP lookup on VirusTotal"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 80, "undetected": 13},
                    "as_owner": "Google LLC",
                    "country": "US",
                }
            }
        }
        mock_get.return_value = mock_response

        api = VirusTotalAPI("test_key")
        result = api.lookup_ip("8.8.8.8")

        assert result["source"] == "virustotal"
        assert result["malicious"] == 5
        assert result["suspicious"] == 2
        assert result["as_owner"] == "Google LLC"

    @patch("requests.get")
    def test_lookup_domain_success(self, mock_get):
        """Test successful domain lookup on VirusTotal"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10},
                    "categories": {"Fortinet": "Search Engines"},
                    "creation_date": 1577836800,
                }
            }
        }
        mock_get.return_value = mock_response

        api = VirusTotalAPI("test_key")
        result = api.lookup_domain("example.com")

        assert result["source"] == "virustotal"
        assert result["malicious"] == 0
        assert "categories" in result

    @patch("requests.get")
    def test_lookup_error(self, mock_get):
        """Test lookup with error"""
        mock_get.side_effect = Exception("API error")

        api = VirusTotalAPI("test_key")
        result = api.lookup_ip("8.8.8.8")

        assert result["source"] == "virustotal"
        assert "error" in result


class TestDomainIPIntelligence:
    """Test main intelligence orchestrator"""

    def test_init(self):
        """Test intelligence initialization"""
        intel = DomainIPIntelligence(verbose=False)
        assert intel.verbose is False

    def test_analyze_invalid_ip(self):
        """Test analysis of invalid IP"""
        intel = DomainIPIntelligence()
        result = intel.analyze_ip("999.999.999.999")

        assert result["type"] == "invalid"
        assert "error" in result

    @patch("domainIpIntel.intel.DNSLookup.resolve_ptr")
    def test_analyze_private_ip(self, mock_resolve_ptr):
        """Test analysis of private IP"""
        intel = DomainIPIntelligence()
        result = intel.analyze_ip("192.168.1.1")

        assert result["type"] == "ipv4"
        assert result["is_private"] is True
        assert "note" in result
        # Should not have threat intelligence for private IPs
        assert "threat_intelligence" not in result

    @patch("domainIpIntel.intel.VirusTotalAPI")
    @patch("domainIpIntel.intel.AbuseIPDBAPI")
    @patch("domainIpIntel.intel.DNSLookup.resolve_ptr")
    def test_analyze_public_ip(self, mock_resolve_ptr, mock_abuseipdb, mock_vt):
        """Test analysis of public IP with mocked APIs"""
        # Mock PTR record
        mock_resolve_ptr.return_value = "example.com"

        # Mock AbuseIPDB
        mock_abuseipdb_instance = Mock()
        mock_abuseipdb_instance.lookup_ip.return_value = {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
        }
        mock_abuseipdb.return_value = mock_abuseipdb_instance

        # Mock VirusTotal
        mock_vt_instance = Mock()
        mock_vt_instance.lookup_ip.return_value = {"source": "virustotal", "malicious": 0, "suspicious": 0}
        mock_vt.return_value = mock_vt_instance

        intel = DomainIPIntelligence()
        result = intel.analyze_ip("8.8.8.8")

        assert result["type"] == "ipv4"
        assert result["is_private"] is False
        assert result["reverse_dns"] == "example.com"
        assert "threat_intelligence" in result
        assert "reputation" in result
        assert result["reputation"]["risk_level"] == "Clean"

    def test_analyze_invalid_domain(self):
        """Test analysis of invalid domain"""
        intel = DomainIPIntelligence()
        result = intel.analyze_domain("invalid_domain")

        assert result["type"] == "invalid"
        assert "error" in result

    @patch("domainIpIntel.intel.VirusTotalAPI")
    @patch("domainIpIntel.intel.DNSLookup.get_dns_info")
    def test_analyze_valid_domain(self, mock_dns, mock_vt):
        """Test analysis of valid domain with mocked APIs"""
        # Mock DNS info
        mock_dns.return_value = {"a_records": ["93.184.216.34"], "reverse_dns": {"93.184.216.34": "example.com"}}

        # Mock VirusTotal
        mock_vt_instance = Mock()
        mock_vt_instance.lookup_domain.return_value = {"source": "virustotal", "malicious": 0, "suspicious": 0}
        mock_vt.return_value = mock_vt_instance

        intel = DomainIPIntelligence()
        result = intel.analyze_domain("example.com")

        assert result["type"] == "domain"
        assert result["target"] == "example.com"
        assert "dns" in result
        assert "threat_intelligence" in result
        assert "reputation" in result

    def test_analyze_auto_detect_ip(self):
        """Test auto-detection of IP"""
        intel = DomainIPIntelligence()
        result = intel.analyze("8.8.8.8")

        assert result["type"] == "ipv4"

    def test_analyze_auto_detect_domain(self):
        """Test auto-detection of domain"""
        intel = DomainIPIntelligence()
        result = intel.analyze("example.com")

        # Should attempt domain analysis (may fail if no network)
        assert result["type"] in ["domain", "invalid"]

    def test_analyze_auto_detect_unknown(self):
        """Test auto-detection with unknown format"""
        intel = DomainIPIntelligence()
        result = intel.analyze("not-an-ip-or-domain!")

        assert result["type"] == "unknown"
        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
