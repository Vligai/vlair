#!/usr/bin/env python3
"""
IOC Hunt Workflow
Bulk IOC investigation from a list
"""

import sys
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.workflow import Workflow, WorkflowStep, StepResult, WorkflowContext, workflow
from core.scorer import Severity


@workflow
class IOCHuntWorkflow(Workflow):
    """
    IOC Hunt Workflow

    Steps:
    1. Parse IOC list file
    2. Categorize IOCs by type (hash, domain, IP, URL)
    3. Check hashes against threat intelligence
    4. Check domains against reputation services
    5. Check IPs against threat intelligence
    6. Check URLs for malicious indicators
    7. Generate summary report with hit rates
    """

    @property
    def name(self) -> str:
        return "ioc-hunt"

    @property
    def description(self) -> str:
        return "Bulk IOC threat hunting"

    def _define_steps(self):
        self.steps = [
            WorkflowStep(name="parse_iocs", description="Parse and categorize IOC list", tool="ioc_extractor", required=True),
            WorkflowStep(
                name="check_hashes",
                description="Check hashes against threat intel",
                tool="hash_lookup",
                required=False,
                depends_on=["parse_iocs"],
            ),
            WorkflowStep(
                name="check_domains",
                description="Check domains against reputation",
                tool="domain_intel",
                required=False,
                depends_on=["parse_iocs"],
            ),
            WorkflowStep(
                name="check_ips",
                description="Check IPs against threat intel",
                tool="domain_intel",
                required=False,
                depends_on=["parse_iocs"],
            ),
            WorkflowStep(
                name="check_urls",
                description="Check URLs for threats",
                tool="url_analyzer",
                required=False,
                depends_on=["parse_iocs"],
            ),
            WorkflowStep(name="generate_report", description="Generate summary report", tool="internal", required=True),
        ]

    def _execute_step(self, step: WorkflowStep, context: WorkflowContext) -> StepResult:
        if step.name == "parse_iocs":
            return self._parse_iocs(context)
        elif step.name == "check_hashes":
            return self._check_hashes(context)
        elif step.name == "check_domains":
            return self._check_domains(context)
        elif step.name == "check_ips":
            return self._check_ips(context)
        elif step.name == "check_urls":
            return self._check_urls(context)
        elif step.name == "generate_report":
            return self._generate_report(context)
        else:
            return StepResult(step_name=step.name, success=False, error="Unknown step")

    def _parse_iocs(self, context: WorkflowContext) -> StepResult:
        """Parse IOC list file"""
        try:
            from iocExtractor.extractor import IOCExtractor

            extractor = IOCExtractor(exclude_private_ips=True, refang=True)
            result = extractor.extract_from_file(context.input_value)

            # Add IOCs to context
            context.add_iocs("hashes", result.get("md5", []) + result.get("sha1", []) + result.get("sha256", []))
            context.add_iocs("domains", result.get("domains", []))
            context.add_iocs("ips", result.get("ips", []))
            context.add_iocs("urls", result.get("urls", []))

            context.add_tool_result("ioc_extractor", result)

            # Store counts for reporting
            context.data["ioc_counts"] = {
                "hashes": len(context.iocs["hashes"]),
                "domains": len(context.iocs["domains"]),
                "ips": len(context.iocs["ips"]),
                "urls": len(context.iocs["urls"]),
            }

            total = sum(context.data["ioc_counts"].values())
            self._log(f"  Found {total} IOCs to check")

            return StepResult(step_name="parse_iocs", success=True, data=context.data["ioc_counts"])

        except Exception as e:
            return StepResult(step_name="parse_iocs", success=False, error=str(e))

    def _check_hashes(self, context: WorkflowContext) -> StepResult:
        """Check hashes against threat intelligence"""
        hashes = context.iocs.get("hashes", [])
        if not hashes:
            return StepResult(step_name="check_hashes", success=True, data={"checked": 0})

        try:
            from hashLookup.lookup import HashLookup

            lookup = HashLookup(verbose=self.verbose)

            results = {"checked": 0, "malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
            malicious_hashes = []

            for hash_val in hashes[:20]:  # Limit to 20
                result = lookup.lookup(hash_val)
                results["checked"] += 1

                verdict = result.get("verdict", "unknown")
                if verdict == "malicious":
                    results["malicious"] += 1
                    malicious_hashes.append(hash_val)
                elif verdict == "suspicious":
                    results["suspicious"] += 1
                elif verdict == "clean":
                    results["clean"] += 1
                else:
                    results["unknown"] += 1

            if malicious_hashes:
                context.scorer.add_finding(
                    Severity.CRITICAL,
                    f"{len(malicious_hashes)} malicious hashes found",
                    "hash_lookup",
                    {"malicious_hashes": malicious_hashes[:5]},
                )

            context.data["hash_results"] = results
            context.add_tool_result("hash_lookup", results)
            return StepResult(step_name="check_hashes", success=True, data=results)

        except Exception as e:
            return StepResult(step_name="check_hashes", success=False, error=str(e))

    def _check_domains(self, context: WorkflowContext) -> StepResult:
        """Check domains against reputation services"""
        domains = context.iocs.get("domains", [])
        if not domains:
            return StepResult(step_name="check_domains", success=True, data={"checked": 0})

        try:
            from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

            intel = DomainIPIntel(verbose=self.verbose)

            results = {"checked": 0, "malicious": 0, "suspicious": 0, "clean": 0}
            malicious_domains = []

            for domain in domains[:20]:
                result = intel.lookup(domain)
                results["checked"] += 1

                verdict = result.get("verdict", "unknown")
                if verdict == "malicious":
                    results["malicious"] += 1
                    malicious_domains.append(domain)
                elif verdict == "suspicious":
                    results["suspicious"] += 1
                else:
                    results["clean"] += 1

            if malicious_domains:
                context.scorer.add_finding(
                    Severity.HIGH,
                    f"{len(malicious_domains)} malicious domains found",
                    "domain_intel",
                    {"malicious_domains": malicious_domains[:5]},
                )

            context.data["domain_results"] = results
            context.add_tool_result("domain_intel", results)
            return StepResult(step_name="check_domains", success=True, data=results)

        except Exception as e:
            return StepResult(step_name="check_domains", success=False, error=str(e))

    def _check_ips(self, context: WorkflowContext) -> StepResult:
        """Check IPs against threat intelligence"""
        ips = context.iocs.get("ips", [])
        if not ips:
            return StepResult(step_name="check_ips", success=True, data={"checked": 0})

        try:
            from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

            intel = DomainIPIntel(verbose=self.verbose)

            results = {"checked": 0, "malicious": 0, "suspicious": 0, "clean": 0}
            malicious_ips = []

            for ip in ips[:20]:
                result = intel.lookup(ip)
                results["checked"] += 1

                verdict = result.get("verdict", "unknown")
                if verdict == "malicious":
                    results["malicious"] += 1
                    malicious_ips.append(ip)
                elif verdict == "suspicious":
                    results["suspicious"] += 1
                else:
                    results["clean"] += 1

            if malicious_ips:
                context.scorer.add_finding(
                    Severity.HIGH,
                    f"{len(malicious_ips)} malicious IPs found",
                    "domain_intel",
                    {"malicious_ips": malicious_ips[:5]},
                )

            context.data["ip_results"] = results
            return StepResult(step_name="check_ips", success=True, data=results)

        except Exception as e:
            return StepResult(step_name="check_ips", success=False, error=str(e))

    def _check_urls(self, context: WorkflowContext) -> StepResult:
        """Check URLs for threats"""
        urls = context.iocs.get("urls", [])
        if not urls:
            return StepResult(step_name="check_urls", success=True, data={"checked": 0})

        try:
            from urlAnalyzer.analyzer import URLAnalyzer

            analyzer = URLAnalyzer(verbose=self.verbose)

            results = {"checked": 0, "malicious": 0, "suspicious": 0, "clean": 0}
            malicious_urls = []

            for url in urls[:20]:
                result = analyzer.analyze(url)
                results["checked"] += 1

                verdict = result.get("verdict", "unknown")
                if verdict == "malicious":
                    results["malicious"] += 1
                    malicious_urls.append(url)
                elif verdict == "suspicious":
                    results["suspicious"] += 1
                else:
                    results["clean"] += 1

            if malicious_urls:
                context.scorer.add_finding(
                    Severity.HIGH,
                    f"{len(malicious_urls)} malicious URLs found",
                    "url_analyzer",
                    {"malicious_urls": malicious_urls[:5]},
                )

            context.data["url_results"] = results
            context.add_tool_result("url_analyzer", results)
            return StepResult(step_name="check_urls", success=True, data=results)

        except Exception as e:
            return StepResult(step_name="check_urls", success=False, error=str(e))

    def _generate_report(self, context: WorkflowContext) -> StepResult:
        """Generate summary report"""
        summary = context.scorer.get_summary()

        total_checked = sum(
            [
                context.data.get("hash_results", {}).get("checked", 0),
                context.data.get("domain_results", {}).get("checked", 0),
                context.data.get("ip_results", {}).get("checked", 0),
                context.data.get("url_results", {}).get("checked", 0),
            ]
        )

        total_malicious = sum(
            [
                context.data.get("hash_results", {}).get("malicious", 0),
                context.data.get("domain_results", {}).get("malicious", 0),
                context.data.get("ip_results", {}).get("malicious", 0),
                context.data.get("url_results", {}).get("malicious", 0),
            ]
        )

        hit_rate = (total_malicious / total_checked * 100) if total_checked > 0 else 0

        recommendations = []
        if total_malicious > 0:
            recommendations.extend(
                [
                    "Block all identified malicious IOCs",
                    "Search logs for connections to these IOCs",
                    "Investigate systems that communicated with these IOCs",
                    "Update threat detection rules",
                ]
            )
        else:
            recommendations.append("No malicious IOCs found - continue monitoring")

        return StepResult(
            step_name="generate_report",
            success=True,
            data={
                "total_iocs": sum(context.data.get("ioc_counts", {}).values()),
                "total_checked": total_checked,
                "total_malicious": total_malicious,
                "hit_rate_percent": round(hit_rate, 1),
                "risk_score": summary["risk_score"],
                "verdict": summary["verdict"],
                "recommendations": recommendations,
            },
        )
