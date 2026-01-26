#!/usr/bin/env python3
"""
STIX 2.1 Export Module

Converts SecOps Helper outputs to STIX 2.1 format for sharing threat intelligence.
STIX (Structured Threat Information Expression) is a standardized language for
cyber threat intelligence.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional


class STIXExporter:
    """Export IOCs and analysis results to STIX 2.1 format"""

    def __init__(self, identity_name: str = "SecOps Helper", identity_class: str = "system"):
        """
        Initialize STIX exporter

        Args:
            identity_name: Name of the organization/tool creating STIX objects
            identity_class: Class of identity (system, organization, individual)
        """
        self.identity_name = identity_name
        self.identity_class = identity_class
        self.identity_id = self._generate_stix_id("identity")
        self.created = self._get_timestamp()

    def _generate_stix_id(self, stix_type: str) -> str:
        """Generate a STIX 2.1 compliant ID"""
        return f"{stix_type}--{str(uuid.uuid4())}"

    def _get_timestamp(self) -> str:
        """Get current timestamp in STIX format"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _create_identity(self) -> Dict:
        """Create identity object for the creator"""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": self.created,
            "modified": self.created,
            "name": self.identity_name,
            "identity_class": self.identity_class,
        }

    def _create_indicator(
        self, pattern: str, ioc_type: str, name: str = None, description: str = None, labels: List[str] = None
    ) -> Dict:
        """
        Create STIX indicator object

        Args:
            pattern: STIX pattern (e.g., "[ipv4-addr:value = '192.0.2.1']")
            ioc_type: Type of indicator
            name: Optional name for the indicator
            description: Optional description
            labels: Optional list of labels

        Returns:
            STIX indicator object
        """
        timestamp = self._get_timestamp()

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": self._generate_stix_id("indicator"),
            "created": timestamp,
            "modified": timestamp,
            "created_by_ref": self.identity_id,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": timestamp,
            "indicator_types": [ioc_type],
        }

        if name:
            indicator["name"] = name
        if description:
            indicator["description"] = description
        if labels:
            indicator["labels"] = labels

        return indicator

    def export_iocs(self, ioc_data: Dict, description: str = None, labels: List[str] = None) -> str:
        """
        Export IOC extraction results to STIX 2.1 bundle

        Args:
            ioc_data: IOC data from IOCExtractor
            description: Optional description for all indicators
            labels: Optional labels to apply to all indicators

        Returns:
            JSON string containing STIX bundle
        """
        objects = []

        # Add identity
        objects.append(self._create_identity())

        # Default labels
        if not labels:
            labels = ["malicious-activity"]

        # Process IPs
        for ip in ioc_data.get("ips", []):
            # Remove defanging if present
            clean_ip = ip.replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[ipv4-addr:value = '{clean_ip}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"Malicious IP: {clean_ip}",
                description=description,
                labels=labels,
            )
            objects.append(indicator)

        # Process domains
        for domain in ioc_data.get("domains", []):
            # Remove defanging if present
            clean_domain = domain.replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[domain-name:value = '{clean_domain}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"Malicious Domain: {clean_domain}",
                description=description,
                labels=labels,
            )
            objects.append(indicator)

        # Process URLs
        for url in ioc_data.get("urls", []):
            # Remove defanging if present
            clean_url = url.replace("hxxp", "http").replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[url:value = '{clean_url}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"Malicious URL: {clean_url}",
                description=description,
                labels=labels,
            )
            objects.append(indicator)

        # Process email addresses
        for email in ioc_data.get("emails", []):
            # Remove defanging if present
            clean_email = email.replace("[@]", "@").replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[email-addr:value = '{clean_email}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"Malicious Email: {clean_email}",
                description=description,
                labels=labels,
            )
            objects.append(indicator)

        # Process hashes
        hashes = ioc_data.get("hashes", {})
        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            for hash_value in hashes.get(hash_type, []):
                hash_type_upper = hash_type.upper().replace("SHA", "SHA-")
                pattern = f"[file:hashes.'{hash_type_upper}' = '{hash_value}']"
                indicator = self._create_indicator(
                    pattern=pattern,
                    ioc_type="malicious-activity",
                    name=f"Malicious File Hash ({hash_type_upper}): {hash_value[:16]}...",
                    description=description,
                    labels=labels,
                )
                objects.append(indicator)

        # Create STIX bundle
        bundle = {"type": "bundle", "id": self._generate_stix_id("bundle"), "objects": objects}

        return json.dumps(bundle, indent=2)

    def export_threat_report(
        self, title: str, description: str, ioc_data: Dict, confidence: int = 50, threat_actor: str = None
    ) -> str:
        """
        Export comprehensive threat report as STIX 2.1 bundle

        Args:
            title: Report title
            description: Report description
            ioc_data: IOC data from IOCExtractor
            confidence: Confidence level (0-100)
            threat_actor: Optional threat actor name

        Returns:
            JSON string containing STIX bundle
        """
        objects = []
        timestamp = self._get_timestamp()

        # Add identity
        identity = self._create_identity()
        objects.append(identity)

        # Create report object
        report_id = self._generate_stix_id("report")
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": timestamp,
            "modified": timestamp,
            "created_by_ref": self.identity_id,
            "name": title,
            "description": description,
            "published": timestamp,
            "report_types": ["threat-report"],
            "object_refs": [],
        }

        # Create threat actor if specified
        if threat_actor:
            actor = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": self._generate_stix_id("threat-actor"),
                "created": timestamp,
                "modified": timestamp,
                "created_by_ref": self.identity_id,
                "name": threat_actor,
                "threat_actor_types": ["unknown"],
                "labels": ["malicious-activity"],
            }
            objects.append(actor)
            report["object_refs"].append(actor["id"])

        # Add indicators
        labels = ["malicious-activity"]
        if threat_actor:
            labels.append(threat_actor.lower().replace(" ", "-"))

        # Process all IOCs
        for ip in ioc_data.get("ips", []):
            clean_ip = ip.replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[ipv4-addr:value = '{clean_ip}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"IP: {clean_ip}",
                description=f"IP address associated with {threat_actor or 'malicious activity'}",
                labels=labels,
            )
            objects.append(indicator)
            report["object_refs"].append(indicator["id"])

        for domain in ioc_data.get("domains", []):
            clean_domain = domain.replace("[.]", ".").replace("[", "").replace("]", "")
            pattern = f"[domain-name:value = '{clean_domain}']"
            indicator = self._create_indicator(
                pattern=pattern,
                ioc_type="malicious-activity",
                name=f"Domain: {clean_domain}",
                description=f"Domain associated with {threat_actor or 'malicious activity'}",
                labels=labels,
            )
            objects.append(indicator)
            report["object_refs"].append(indicator["id"])

        # Create bundle
        bundle = {"type": "bundle", "id": self._generate_stix_id("bundle"), "objects": objects}

        return json.dumps(bundle, indent=2)


def export_to_stix(
    ioc_data: Dict, output_type: str = "simple", title: str = None, description: str = None, threat_actor: str = None
) -> str:
    """
    Convenience function to export IOCs to STIX format

    Args:
        ioc_data: IOC data dictionary
        output_type: 'simple' for basic indicators, 'report' for full threat report
        title: Report title (for report type)
        description: Report description
        threat_actor: Threat actor name (for report type)

    Returns:
        JSON string containing STIX bundle
    """
    exporter = STIXExporter()

    if output_type == "report":
        if not title:
            title = "Threat Intelligence Report"
        if not description:
            description = "IOCs extracted by SecOps Helper"
        return exporter.export_threat_report(
            title=title, description=description, ioc_data=ioc_data, threat_actor=threat_actor
        )
    else:
        return exporter.export_iocs(ioc_data=ioc_data, description=description)
