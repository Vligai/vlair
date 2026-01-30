#!/usr/bin/env python3
"""
Unit tests for STIX Export Module
Tests STIX 2.1 format export functionality
"""

import pytest
import sys
import json
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.common.stix_export import STIXExporter, export_to_stix


class TestSTIXExporter:
    """Test STIXExporter class"""

    def test_init_default(self):
        """Test default initialization"""
        exporter = STIXExporter()
        assert exporter.identity_name == "SecOps Helper"
        assert exporter.identity_class == "system"
        assert exporter.identity_id.startswith("identity--")

    def test_init_custom(self):
        """Test custom initialization"""
        exporter = STIXExporter(identity_name="Test Org", identity_class="organization")
        assert exporter.identity_name == "Test Org"
        assert exporter.identity_class == "organization"

    def test_generate_stix_id(self):
        """Test STIX ID generation"""
        exporter = STIXExporter()

        indicator_id = exporter._generate_stix_id("indicator")
        assert indicator_id.startswith("indicator--")

        report_id = exporter._generate_stix_id("report")
        assert report_id.startswith("report--")

    def test_get_timestamp(self):
        """Test timestamp generation"""
        exporter = STIXExporter()
        timestamp = exporter._get_timestamp()

        # Should be ISO format with Z suffix
        assert timestamp.endswith("Z")
        assert "T" in timestamp

    def test_create_identity(self):
        """Test identity object creation"""
        exporter = STIXExporter()
        identity = exporter._create_identity()

        assert identity["type"] == "identity"
        assert identity["spec_version"] == "2.1"
        assert identity["name"] == "SecOps Helper"
        assert identity["identity_class"] == "system"
        assert "id" in identity
        assert "created" in identity
        assert "modified" in identity

    def test_create_indicator(self):
        """Test indicator object creation"""
        exporter = STIXExporter()

        indicator = exporter._create_indicator(
            pattern="[ipv4-addr:value = '192.168.1.1']",
            ioc_type="malicious-activity",
            name="Test IP",
            description="Test description",
            labels=["test-label"],
        )

        assert indicator["type"] == "indicator"
        assert indicator["spec_version"] == "2.1"
        assert indicator["pattern"] == "[ipv4-addr:value = '192.168.1.1']"
        assert indicator["pattern_type"] == "stix"
        assert indicator["name"] == "Test IP"
        assert indicator["description"] == "Test description"
        assert indicator["labels"] == ["test-label"]
        assert indicator["indicator_types"] == ["malicious-activity"]

    def test_create_indicator_minimal(self):
        """Test indicator creation with minimal args"""
        exporter = STIXExporter()

        indicator = exporter._create_indicator(
            pattern="[domain-name:value = 'evil.com']",
            ioc_type="malicious-activity",
        )

        assert indicator["type"] == "indicator"
        assert "name" not in indicator
        assert "description" not in indicator
        assert "labels" not in indicator


class TestExportIOCs:
    """Test IOC export functionality"""

    def test_export_empty_iocs(self):
        """Test exporting empty IOC data"""
        exporter = STIXExporter()
        result = exporter.export_iocs({})

        bundle = json.loads(result)
        assert bundle["type"] == "bundle"
        # Should only have identity object
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0]["type"] == "identity"

    def test_export_ips(self):
        """Test exporting IP addresses"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1", "10.0.0.1"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        # 1 identity + 2 indicators
        assert len(bundle["objects"]) == 3

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 2

        patterns = [ind["pattern"] for ind in indicators]
        assert "[ipv4-addr:value = '192.168.1.1']" in patterns
        assert "[ipv4-addr:value = '10.0.0.1']" in patterns

    def test_export_defanged_ips(self):
        """Test exporting defanged IP addresses"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192[.]168[.]1[.]1"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert indicators[0]["pattern"] == "[ipv4-addr:value = '192.168.1.1']"

    def test_export_domains(self):
        """Test exporting domains"""
        exporter = STIXExporter()
        ioc_data = {"domains": ["evil.com", "malware.net"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 2

        patterns = [ind["pattern"] for ind in indicators]
        assert "[domain-name:value = 'evil.com']" in patterns
        assert "[domain-name:value = 'malware.net']" in patterns

    def test_export_urls(self):
        """Test exporting URLs"""
        exporter = STIXExporter()
        ioc_data = {"urls": ["https://evil.com/malware.exe"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 1
        assert "[url:value = 'https://evil.com/malware.exe']" in indicators[0]["pattern"]

    def test_export_defanged_urls(self):
        """Test exporting defanged URLs"""
        exporter = STIXExporter()
        ioc_data = {"urls": ["hxxps://evil[.]com/malware"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert "[url:value = 'https://evil.com/malware']" in indicators[0]["pattern"]

    def test_export_emails(self):
        """Test exporting email addresses"""
        exporter = STIXExporter()
        ioc_data = {"emails": ["attacker@evil.com"]}

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 1
        assert "[email-addr:value = 'attacker@evil.com']" in indicators[0]["pattern"]

    def test_export_hashes(self):
        """Test exporting file hashes"""
        exporter = STIXExporter()
        ioc_data = {
            "hashes": {
                "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
                "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            }
        }

        result = exporter.export_iocs(ioc_data)
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 2

        patterns = [ind["pattern"] for ind in indicators]
        assert any("MD5" in p for p in patterns)
        assert any("SHA-256" in p for p in patterns)

    def test_export_with_description(self):
        """Test exporting with custom description"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1"]}

        result = exporter.export_iocs(ioc_data, description="Test campaign")
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert indicators[0]["description"] == "Test campaign"

    def test_export_with_labels(self):
        """Test exporting with custom labels"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1"]}

        result = exporter.export_iocs(ioc_data, labels=["apt", "ransomware"])
        bundle = json.loads(result)

        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert indicators[0]["labels"] == ["apt", "ransomware"]


class TestExportThreatReport:
    """Test threat report export functionality"""

    def test_export_basic_report(self):
        """Test basic threat report export"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1"]}

        result = exporter.export_threat_report(
            title="Test Report",
            description="Test description",
            ioc_data=ioc_data,
        )

        bundle = json.loads(result)
        assert bundle["type"] == "bundle"

        # Should have identity, report, and indicator
        types = [obj["type"] for obj in bundle["objects"]]
        assert "identity" in types
        assert "report" in types
        assert "indicator" in types

    def test_export_report_with_threat_actor(self):
        """Test threat report with threat actor"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1"]}

        result = exporter.export_threat_report(
            title="APT Report",
            description="APT campaign analysis",
            ioc_data=ioc_data,
            threat_actor="APT99",
        )

        bundle = json.loads(result)

        # Should have threat-actor
        types = [obj["type"] for obj in bundle["objects"]]
        assert "threat-actor" in types

        actor = next(obj for obj in bundle["objects"] if obj["type"] == "threat-actor")
        assert actor["name"] == "APT99"

    def test_report_references_indicators(self):
        """Test that report references its indicators"""
        exporter = STIXExporter()
        ioc_data = {"ips": ["192.168.1.1"]}

        result = exporter.export_threat_report(
            title="Test Report",
            description="Test description",
            ioc_data=ioc_data,
        )

        bundle = json.loads(result)

        report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
        indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")

        assert indicator["id"] in report["object_refs"]


class TestExportToStixFunction:
    """Test convenience export_to_stix function"""

    def test_simple_export(self):
        """Test simple IOC export"""
        ioc_data = {"ips": ["192.168.1.1"]}

        result = export_to_stix(ioc_data)
        bundle = json.loads(result)

        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 2  # identity + indicator

    def test_report_export(self):
        """Test report export"""
        ioc_data = {"ips": ["192.168.1.1"]}

        result = export_to_stix(
            ioc_data,
            output_type="report",
            title="Custom Title",
            description="Custom Description",
        )

        bundle = json.loads(result)

        report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
        assert report["name"] == "Custom Title"
        assert report["description"] == "Custom Description"

    def test_report_export_defaults(self):
        """Test report export with default title/description"""
        ioc_data = {"domains": ["evil.com"]}

        result = export_to_stix(ioc_data, output_type="report")
        bundle = json.loads(result)

        report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
        assert report["name"] == "Threat Intelligence Report"
        assert "SecOps Helper" in report["description"]

    def test_report_with_threat_actor(self):
        """Test report export with threat actor"""
        ioc_data = {"domains": ["evil.com"]}

        result = export_to_stix(
            ioc_data,
            output_type="report",
            threat_actor="BadGuys",
        )

        bundle = json.loads(result)

        types = [obj["type"] for obj in bundle["objects"]]
        assert "threat-actor" in types
