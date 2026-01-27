#!/usr/bin/env python3
"""
Risk Scorer - Calculate risk scores and verdicts from tool results
Part of SecOps Helper Operationalization (Phase 5)
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class Verdict(Enum):
    """Analysis verdict levels"""

    CLEAN = "CLEAN"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class Severity(Enum):
    """Finding severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a single finding from analysis"""

    severity: Severity
    message: str
    source: str  # Which tool produced this finding
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "message": self.message,
            "source": self.source,
            "details": self.details or {},
        }


class RiskScorer:
    """
    Calculate risk scores from tool results.
    Aggregates findings and produces a final verdict.
    """

    # Score weights by severity
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 15,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    # Maximum contribution per severity (prevents single category from maxing score)
    SEVERITY_CAPS = {
        Severity.CRITICAL: 75,
        Severity.HIGH: 40,
        Severity.MEDIUM: 15,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }

    def __init__(self):
        self.findings: List[Finding] = []

    def add_finding(
        self,
        severity: Severity,
        message: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Add a finding to the scorer."""
        self.findings.append(Finding(severity, message, source, details))

    def add_findings_from_hash_lookup(self, result: Dict[str, Any]):
        """Extract findings from hash lookup result."""
        if not result or "error" in result:
            return

        # Check VirusTotal results
        vt = result.get("sources", {}).get("virustotal", {})
        if vt:
            detections = vt.get("detections", 0)
            total = vt.get("total", 0)

            if detections > 0:
                ratio = detections / total if total > 0 else 0
                if ratio > 0.5:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"Hash detected as malicious by {detections}/{total} AV engines",
                        "hash_lookup",
                        {"detections": detections, "total": total, "ratio": ratio},
                    )
                elif ratio > 0.2:
                    self.add_finding(
                        Severity.HIGH,
                        f"Hash flagged by {detections}/{total} AV engines",
                        "hash_lookup",
                        {"detections": detections, "total": total},
                    )
                else:
                    self.add_finding(
                        Severity.MEDIUM,
                        f"Hash has some detections ({detections}/{total})",
                        "hash_lookup",
                        {"detections": detections, "total": total},
                    )

        # Check MalwareBazaar results
        mb = result.get("sources", {}).get("malwarebazaar", {})
        if mb and mb.get("found"):
            family = mb.get("malware_family", "Unknown")
            self.add_finding(
                Severity.CRITICAL,
                f"Hash matches known malware family: {family}",
                "hash_lookup",
                {"malware_family": family, "source": "MalwareBazaar"},
            )

    def add_findings_from_domain_intel(self, result: Dict[str, Any]):
        """Extract findings from domain/IP intel result."""
        if not result or "error" in result:
            return

        # Check risk score from tool
        risk_score = result.get("risk_score", 0)
        verdict = result.get("verdict", "").upper()

        if verdict == "MALICIOUS" or risk_score >= 70:
            self.add_finding(
                Severity.CRITICAL,
                f"Domain/IP flagged as malicious (risk: {risk_score})",
                "domain_intel",
                {"risk_score": risk_score},
            )
        elif verdict == "SUSPICIOUS" or risk_score >= 40:
            self.add_finding(
                Severity.HIGH,
                f"Domain/IP is suspicious (risk: {risk_score})",
                "domain_intel",
                {"risk_score": risk_score},
            )

        # Check individual sources
        vt = result.get("sources", {}).get("virustotal", {})
        if vt:
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                self.add_finding(
                    Severity.HIGH,
                    f"VirusTotal: {malicious} vendors flagged as malicious",
                    "domain_intel",
                    {"malicious_count": malicious},
                )

        abuse = result.get("sources", {}).get("abuseipdb", {})
        if abuse:
            confidence = abuse.get("abuse_confidence", 0)
            if confidence > 50:
                self.add_finding(
                    Severity.HIGH,
                    f"AbuseIPDB: {confidence}% abuse confidence",
                    "domain_intel",
                    {"abuse_confidence": confidence},
                )

    def add_findings_from_url_analysis(self, result: Dict[str, Any]):
        """Extract findings from URL analysis result."""
        if not result or "error" in result:
            return

        verdict = result.get("verdict", "").upper()
        risk_score = result.get("risk_score", 0)

        if verdict == "MALICIOUS" or risk_score >= 70:
            self.add_finding(
                Severity.CRITICAL,
                f"URL flagged as malicious (risk: {risk_score})",
                "url_analyzer",
                {"risk_score": risk_score},
            )
        elif verdict == "SUSPICIOUS" or risk_score >= 40:
            self.add_finding(
                Severity.HIGH,
                f"URL is suspicious (risk: {risk_score})",
                "url_analyzer",
                {"risk_score": risk_score},
            )

        # Check for specific patterns
        patterns = result.get("suspicious_patterns", [])
        if patterns:
            self.add_finding(
                Severity.MEDIUM,
                f"URL has {len(patterns)} suspicious patterns",
                "url_analyzer",
                {"patterns": patterns},
            )

    def add_findings_from_email_analysis(self, result: Dict[str, Any]):
        """Extract findings from email analysis result."""
        if not result or "error" in result:
            return

        # Check authentication
        auth = result.get("authentication", {})

        spf = auth.get("spf", {})
        if spf.get("result") == "fail":
            self.add_finding(
                Severity.HIGH,
                "SPF validation failed - sender may be spoofed",
                "eml_parser",
                {"spf_result": spf},
            )

        dkim = auth.get("dkim", {})
        if dkim.get("result") == "fail":
            self.add_finding(
                Severity.MEDIUM, "DKIM validation failed", "eml_parser", {"dkim_result": dkim}
            )

        dmarc = auth.get("dmarc", {})
        if dmarc.get("result") == "fail":
            self.add_finding(
                Severity.HIGH, "DMARC validation failed", "eml_parser", {"dmarc_result": dmarc}
            )

        # Check attachments
        attachments = result.get("attachments", [])
        for att in attachments:
            if att.get("vt_detections", 0) > 0:
                self.add_finding(
                    Severity.CRITICAL,
                    f"Attachment '{att.get('filename')}' flagged as malicious",
                    "eml_parser",
                    {"attachment": att},
                )

    def add_findings_from_yara_scan(self, result: Dict[str, Any]):
        """Extract findings from YARA scan result."""
        if not result or "error" in result:
            return

        matches = result.get("matches", [])
        for match in matches:
            rule = match.get("rule", "Unknown")
            severity_str = match.get("severity", "medium").lower()

            # Map YARA severity to our severity
            if severity_str == "critical":
                sev = Severity.CRITICAL
            elif severity_str == "high":
                sev = Severity.HIGH
            elif severity_str == "medium":
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            self.add_finding(
                sev,
                f"YARA rule matched: {rule}",
                "yara_scanner",
                {"rule": rule, "meta": match.get("meta", {})},
            )

    def add_findings_from_log_analysis(self, result: Dict[str, Any]):
        """Extract findings from log analysis result."""
        if not result or "error" in result:
            return

        threats = result.get("threats", {})

        # SQL injection attempts
        sqli = threats.get("sql_injection", [])
        if sqli:
            self.add_finding(
                Severity.CRITICAL,
                f"Detected {len(sqli)} SQL injection attempts",
                "log_analyzer",
                {"count": len(sqli)},
            )

        # XSS attempts
        xss = threats.get("xss", [])
        if xss:
            self.add_finding(
                Severity.HIGH,
                f"Detected {len(xss)} XSS attempts",
                "log_analyzer",
                {"count": len(xss)},
            )

        # Path traversal
        traversal = threats.get("path_traversal", [])
        if traversal:
            self.add_finding(
                Severity.HIGH,
                f"Detected {len(traversal)} path traversal attempts",
                "log_analyzer",
                {"count": len(traversal)},
            )

        # Brute force
        brute = threats.get("brute_force", [])
        if brute:
            self.add_finding(
                Severity.MEDIUM,
                f"Detected brute force patterns from {len(brute)} IPs",
                "log_analyzer",
                {"count": len(brute)},
            )

    def add_findings_from_pcap_analysis(self, result: Dict[str, Any]):
        """Extract findings from PCAP analysis result."""
        if not result or "error" in result:
            return

        threats = result.get("threats", {})

        # Port scans
        port_scans = threats.get("port_scans", [])
        if port_scans:
            self.add_finding(
                Severity.MEDIUM,
                f"Detected port scan activity from {len(port_scans)} sources",
                "pcap_analyzer",
                {"count": len(port_scans)},
            )

        # Suspicious DNS
        dns_threats = threats.get("suspicious_dns", [])
        if dns_threats:
            self.add_finding(
                Severity.HIGH,
                f"Detected {len(dns_threats)} suspicious DNS queries",
                "pcap_analyzer",
                {"count": len(dns_threats)},
            )

        # C2 indicators
        c2 = threats.get("c2_indicators", [])
        if c2:
            self.add_finding(
                Severity.CRITICAL,
                f"Detected potential C2 communication patterns",
                "pcap_analyzer",
                {"indicators": c2},
            )

    def add_findings_from_deobfuscation(self, result: Dict[str, Any]):
        """Extract findings from script deobfuscation result."""
        if not result or "error" in result:
            return

        # Check if obfuscation was detected
        layers = result.get("layers_decoded", 0)
        if layers > 0:
            if layers >= 3:
                self.add_finding(
                    Severity.HIGH,
                    f"Script was heavily obfuscated ({layers} layers)",
                    "deobfuscator",
                    {"layers": layers},
                )
            else:
                self.add_finding(
                    Severity.MEDIUM,
                    f"Script was obfuscated ({layers} layers)",
                    "deobfuscator",
                    {"layers": layers},
                )

        # Check extracted IOCs
        iocs = result.get("extracted_iocs", {})
        if iocs:
            total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
            if total_iocs > 0:
                self.add_finding(
                    Severity.MEDIUM,
                    f"Found {total_iocs} IOCs in deobfuscated script",
                    "deobfuscator",
                    {"iocs": iocs},
                )

    def calculate_score(self) -> int:
        """
        Calculate the final risk score (0-100).

        Returns:
            Integer risk score from 0 (clean) to 100 (definitely malicious)
        """
        score = 0
        severity_totals = {sev: 0 for sev in Severity}

        for finding in self.findings:
            weight = self.SEVERITY_WEIGHTS[finding.severity]
            severity_totals[finding.severity] += weight

        # Apply caps and sum
        for severity, total in severity_totals.items():
            cap = self.SEVERITY_CAPS[severity]
            score += min(total, cap)

        return min(score, 100)

    def get_verdict(self, score: Optional[int] = None) -> Verdict:
        """
        Get the verdict based on risk score.

        Args:
            score: Optional pre-calculated score. If None, calculates it.

        Returns:
            Verdict enum value
        """
        if score is None:
            score = self.calculate_score()

        if score >= 70:
            return Verdict.MALICIOUS
        elif score >= 40:
            return Verdict.SUSPICIOUS
        elif score >= 10:
            return Verdict.LOW_RISK
        elif score > 0:
            return Verdict.CLEAN
        else:
            # No findings at all
            if len(self.findings) == 0:
                return Verdict.UNKNOWN
            return Verdict.CLEAN

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the risk assessment.

        Returns:
            Dict with score, verdict, findings count by severity
        """
        score = self.calculate_score()
        verdict = self.get_verdict(score)

        severity_counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1

        return {
            "risk_score": score,
            "verdict": verdict.value,
            "confidence": self._get_confidence(),
            "finding_counts": severity_counts,
            "total_findings": len(self.findings),
        }

    def _get_confidence(self) -> str:
        """Determine confidence level based on findings."""
        if len(self.findings) == 0:
            return "low"
        if len(self.findings) >= 3:
            return "high"
        return "medium"

    def get_findings(self, min_severity: Optional[Severity] = None) -> List[Dict[str, Any]]:
        """
        Get all findings, optionally filtered by minimum severity.

        Args:
            min_severity: Minimum severity to include

        Returns:
            List of finding dicts
        """
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        if min_severity:
            min_index = severity_order.index(min_severity)
            included = set(severity_order[: min_index + 1])
            findings = [f for f in self.findings if f.severity in included]
        else:
            findings = self.findings

        # Sort by severity (critical first)
        findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

        return [f.to_dict() for f in findings]

    def get_recommendations(self) -> List[str]:
        """
        Generate recommended actions based on findings.

        Returns:
            List of recommendation strings
        """
        recommendations = []
        has_malware = False
        has_phishing = False
        has_network_threat = False
        malicious_iocs = []

        for finding in self.findings:
            details = finding.details or {}

            # Check for malware indicators
            if "malware_family" in details:
                has_malware = True
            if finding.source == "hash_lookup" and finding.severity == Severity.CRITICAL:
                has_malware = True

            # Check for phishing indicators
            if "spf" in str(details) or "dkim" in str(details):
                has_phishing = True

            # Check for network threats
            if finding.source in ["pcap_analyzer", "log_analyzer"]:
                has_network_threat = True

            # Collect malicious IOCs
            if finding.severity == Severity.CRITICAL:
                if "url" in str(finding.message).lower():
                    malicious_iocs.append("url")
                if "domain" in str(finding.message).lower():
                    malicious_iocs.append("domain")
                if "ip" in str(finding.message).lower():
                    malicious_iocs.append("ip")

        # Generate recommendations
        if has_malware:
            recommendations.append("Isolate affected systems immediately")
            recommendations.append("Submit sample to sandbox for detailed analysis")
            recommendations.append("Check for lateral movement indicators")

        if has_phishing:
            recommendations.append("Block sender domain at email gateway")
            recommendations.append("Search for similar emails in organization")
            recommendations.append("Alert users who received this email")

        if has_network_threat:
            recommendations.append("Review firewall logs for additional indicators")
            recommendations.append("Check for data exfiltration attempts")

        if "url" in malicious_iocs or "domain" in malicious_iocs:
            recommendations.append("Block malicious URLs/domains at proxy")

        if "ip" in malicious_iocs:
            recommendations.append("Block malicious IPs at firewall")

        # Generic recommendations based on verdict
        score = self.calculate_score()
        if score >= 70:
            if not recommendations:
                recommendations.append("Escalate to incident response team")
            recommendations.append("Preserve evidence for forensic analysis")
        elif score >= 40:
            recommendations.append("Monitor for additional suspicious activity")
            recommendations.append("Consider blocking associated indicators")

        return recommendations if recommendations else ["No specific actions required"]

    def reset(self):
        """Clear all findings for reuse."""
        self.findings = []


def main():
    """Test the scorer."""
    scorer = RiskScorer()

    # Add some test findings
    scorer.add_finding(
        Severity.CRITICAL,
        "Hash detected as malicious by 45/70 AV engines",
        "hash_lookup",
        {"detections": 45, "total": 70},
    )
    scorer.add_finding(Severity.HIGH, "SPF validation failed", "eml_parser")
    scorer.add_finding(Severity.MEDIUM, "Script was obfuscated (2 layers)", "deobfuscator")

    print("Summary:", scorer.get_summary())
    print("\nFindings:")
    for f in scorer.get_findings():
        print(f"  [{f['severity']}] {f['message']}")
    print("\nRecommendations:")
    for r in scorer.get_recommendations():
        print(f"  - {r}")


if __name__ == "__main__":
    main()
