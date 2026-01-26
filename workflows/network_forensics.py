#!/usr/bin/env python3
"""
Network Forensics Workflow
PCAP analysis for security investigation
"""

import sys
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.workflow import Workflow, WorkflowStep, StepResult, WorkflowContext, workflow
from core.scorer import Severity


@workflow
class NetworkForensicsWorkflow(Workflow):
    """
    Network Forensics Workflow

    Steps:
    1. Parse PCAP file
    2. Extract network IOCs (IPs, domains from DNS)
    3. Detect port scans and reconnaissance
    4. Identify suspicious DNS queries
    5. Check extracted IPs against threat intel
    6. Scan for YARA-detectable patterns
    7. Generate forensics report
    """

    @property
    def name(self) -> str:
        return "network-forensics"

    @property
    def description(self) -> str:
        return "Network traffic forensic analysis"

    def _define_steps(self):
        self.steps = [
            WorkflowStep(name="parse_pcap", description="Parse network capture", tool="pcap_analyzer", required=True),
            WorkflowStep(
                name="extract_iocs",
                description="Extract network IOCs",
                tool="internal",
                required=True,
                depends_on=["parse_pcap"],
            ),
            WorkflowStep(
                name="detect_scans",
                description="Detect port scans and recon",
                tool="internal",
                required=True,
                depends_on=["parse_pcap"],
            ),
            WorkflowStep(
                name="analyze_dns",
                description="Analyze DNS queries",
                tool="internal",
                required=True,
                depends_on=["parse_pcap"],
            ),
            WorkflowStep(
                name="check_ips",
                description="Check IPs against threat intel",
                tool="domain_intel",
                required=False,
                depends_on=["extract_iocs"],
            ),
            WorkflowStep(
                name="yara_scan",
                description="Scan payloads with YARA",
                tool="yara_scanner",
                required=False,
                depends_on=["parse_pcap"],
            ),
            WorkflowStep(name="generate_report", description="Generate forensics report", tool="internal", required=True),
        ]

    def _execute_step(self, step: WorkflowStep, context: WorkflowContext) -> StepResult:
        if step.name == "parse_pcap":
            return self._parse_pcap(context)
        elif step.name == "extract_iocs":
            return self._extract_iocs(context)
        elif step.name == "detect_scans":
            return self._detect_scans(context)
        elif step.name == "analyze_dns":
            return self._analyze_dns(context)
        elif step.name == "check_ips":
            return self._check_ips(context)
        elif step.name == "yara_scan":
            return self._yara_scan(context)
        elif step.name == "generate_report":
            return self._generate_report(context)
        else:
            return StepResult(step_name=step.name, success=False, error="Unknown step")

    def _parse_pcap(self, context: WorkflowContext) -> StepResult:
        """Parse PCAP file"""
        try:
            from pcapAnalyzer.analyzer import PCAPAnalyzer

            analyzer = PCAPAnalyzer(verbose=self.verbose)
            result = analyzer.analyze(context.input_value)

            context.add_tool_result("pcap_analyzer", result)
            context.data["pcap_result"] = result

            # Basic stats
            stats = result.get("statistics", {})
            self._log(f"  {stats.get('total_packets', 0)} packets analyzed")

            return StepResult(step_name="parse_pcap", success=True, data=result)

        except ImportError:
            return StepResult(step_name="parse_pcap", success=False, error="PCAP analyzer not available")
        except Exception as e:
            return StepResult(step_name="parse_pcap", success=False, error=str(e))

    def _extract_iocs(self, context: WorkflowContext) -> StepResult:
        """Extract network IOCs from PCAP results"""
        pcap = context.data.get("pcap_result", {})

        # Extract IPs
        ips = list(pcap.get("ips", {}).keys())[:50]  # Limit to 50
        context.add_iocs("ips", ips)

        # Extract domains from DNS queries
        dns_queries = pcap.get("dns_queries", [])
        domains = [q.get("query") for q in dns_queries if q.get("query")][:50]
        context.add_iocs("domains", domains)

        context.data["network_iocs"] = {"unique_ips": len(ips), "dns_queries": len(domains)}

        return StepResult(step_name="extract_iocs", success=True, data=context.data["network_iocs"])

    def _detect_scans(self, context: WorkflowContext) -> StepResult:
        """Detect port scans and reconnaissance"""
        pcap = context.data.get("pcap_result", {})
        threats = pcap.get("threats", {})

        # Port scans
        port_scans = threats.get("port_scans", [])
        if port_scans:
            context.scorer.add_finding(
                Severity.MEDIUM,
                f"Detected port scan activity from {len(port_scans)} sources",
                "pcap_analyzer",
                {"sources": port_scans[:5]},
            )

        # Check for unusual port activity
        connections = pcap.get("connections", [])
        high_ports = [c for c in connections if c.get("dst_port", 0) > 10000]

        if len(high_ports) > 20:
            context.scorer.add_finding(
                Severity.LOW,
                f"High number of connections to high ports ({len(high_ports)})",
                "pcap_analyzer",
                {"count": len(high_ports)},
            )

        return StepResult(step_name="detect_scans", success=True, data={"port_scans": len(port_scans)})

    def _analyze_dns(self, context: WorkflowContext) -> StepResult:
        """Analyze DNS queries for suspicious patterns"""
        pcap = context.data.get("pcap_result", {})
        threats = pcap.get("threats", {})

        # Suspicious DNS
        suspicious_dns = threats.get("suspicious_dns", [])
        if suspicious_dns:
            context.scorer.add_finding(
                Severity.HIGH,
                f"Detected {len(suspicious_dns)} suspicious DNS queries",
                "pcap_analyzer",
                {"queries": suspicious_dns[:5]},
            )

        # Check for DGA patterns
        dns_queries = pcap.get("dns_queries", [])
        dga_candidates = []

        for query in dns_queries:
            domain = query.get("query", "")
            # Simple DGA detection: high consonant ratio, no common words
            if len(domain) > 15:
                consonants = sum(1 for c in domain.lower() if c in "bcdfghjklmnpqrstvwxyz")
                vowels = sum(1 for c in domain.lower() if c in "aeiou")
                if consonants > vowels * 3:
                    dga_candidates.append(domain)

        if dga_candidates:
            context.scorer.add_finding(
                Severity.HIGH,
                f"Potential DGA domains detected ({len(dga_candidates)})",
                "pcap_analyzer",
                {"domains": dga_candidates[:5]},
            )

        # Check for DNS tunneling (many TXT queries or long queries)
        txt_queries = [q for q in dns_queries if q.get("type") == "TXT"]
        if len(txt_queries) > 10:
            context.scorer.add_finding(
                Severity.MEDIUM,
                f"Many DNS TXT queries detected ({len(txt_queries)}) - possible tunneling",
                "pcap_analyzer",
                {"count": len(txt_queries)},
            )

        return StepResult(
            step_name="analyze_dns",
            success=True,
            data={"suspicious": len(suspicious_dns), "dga_candidates": len(dga_candidates)},
        )

    def _check_ips(self, context: WorkflowContext) -> StepResult:
        """Check extracted IPs against threat intelligence"""
        ips = context.iocs.get("ips", [])

        # Filter out private IPs
        public_ips = [ip for ip in ips if not self._is_private_ip(ip)][:10]

        if not public_ips:
            return StepResult(step_name="check_ips", success=True, data={"checked": 0, "message": "No public IPs to check"})

        try:
            from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

            intel = DomainIPIntel(verbose=self.verbose)

            malicious_count = 0
            for ip in public_ips:
                result = intel.lookup(ip)
                if result.get("verdict") == "malicious":
                    malicious_count += 1
                    context.scorer.add_finding(
                        Severity.CRITICAL, f"Communication with malicious IP: {ip}", "domain_intel", result
                    )

            return StepResult(
                step_name="check_ips", success=True, data={"checked": len(public_ips), "malicious": malicious_count}
            )

        except Exception as e:
            return StepResult(step_name="check_ips", success=False, error=str(e))

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            return False
        except ValueError:
            return False

    def _yara_scan(self, context: WorkflowContext) -> StepResult:
        """Scan PCAP payloads with YARA"""
        try:
            from yaraScanner.scanner import YaraScanner

            scanner = YaraScanner(verbose=self.verbose)
            result = scanner.scan_file(context.input_value)

            matches = result.get("matches", [])
            if matches:
                for match in matches:
                    context.scorer.add_finding(
                        Severity.HIGH, f"YARA match in network traffic: {match.get('rule')}", "yara_scanner", match
                    )

            context.add_tool_result("yara_scanner", result)
            return StepResult(step_name="yara_scan", success=True, data=result)

        except Exception as e:
            return StepResult(step_name="yara_scan", success=False, error=str(e))

    def _generate_report(self, context: WorkflowContext) -> StepResult:
        """Generate forensics report"""
        summary = context.scorer.get_summary()
        pcap = context.data.get("pcap_result", {})

        recommendations = []
        if summary["risk_score"] >= 70:
            recommendations.extend(
                [
                    "Isolate affected systems immediately",
                    "Block identified malicious IPs at firewall",
                    "Capture additional traffic for analysis",
                    "Investigate for data exfiltration",
                    "Check for lateral movement",
                ]
            )
        elif summary["risk_score"] >= 40:
            recommendations.extend(
                ["Monitor identified IPs for additional activity", "Review DNS query patterns", "Correlate with endpoint logs"]
            )
        else:
            recommendations.append("No significant threats detected - continue monitoring")

        return StepResult(
            step_name="generate_report",
            success=True,
            data={
                "total_packets": pcap.get("statistics", {}).get("total_packets", 0),
                "unique_ips": context.data.get("network_iocs", {}).get("unique_ips", 0),
                "dns_queries": context.data.get("network_iocs", {}).get("dns_queries", 0),
                "risk_score": summary["risk_score"],
                "verdict": summary["verdict"],
                "recommendations": recommendations,
            },
        )
