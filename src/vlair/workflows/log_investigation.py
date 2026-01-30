#!/usr/bin/env python3
"""
Log Investigation Workflow
Security log analysis for incident investigation
"""

from pathlib import Path
from typing import Dict, Any

from vlair.core.workflow import (
    Workflow,
    WorkflowStep,
    StepResult,
    WorkflowContext,
    workflow,
)
from vlair.core.scorer import Severity


@workflow
class LogInvestigationWorkflow(Workflow):
    """
    Log Investigation Workflow

    Steps:
    1. Parse log file (auto-detect format)
    2. Detect web attacks (SQL injection, XSS, path traversal)
    3. Detect brute force attempts
    4. Detect scanner activity
    5. Extract attacker IPs
    6. Check attacker IPs against threat intel
    7. Generate investigation report
    """

    @property
    def name(self) -> str:
        return "log-investigation"

    @property
    def description(self) -> str:
        return "Security log investigation"

    def _define_steps(self):
        self.steps = [
            WorkflowStep(
                name="parse_logs",
                description="Parse and analyze log file",
                tool="log_analyzer",
                required=True,
            ),
            WorkflowStep(
                name="detect_attacks",
                description="Detect web attacks",
                tool="internal",
                required=True,
                depends_on=["parse_logs"],
            ),
            WorkflowStep(
                name="detect_bruteforce",
                description="Detect brute force attempts",
                tool="internal",
                required=True,
                depends_on=["parse_logs"],
            ),
            WorkflowStep(
                name="detect_scanners",
                description="Detect scanner activity",
                tool="internal",
                required=True,
                depends_on=["parse_logs"],
            ),
            WorkflowStep(
                name="extract_attackers",
                description="Extract attacker IPs",
                tool="internal",
                required=True,
                depends_on=["parse_logs"],
            ),
            WorkflowStep(
                name="check_ips",
                description="Check IPs against threat intel",
                tool="domain_intel",
                required=False,
                depends_on=["extract_attackers"],
            ),
            WorkflowStep(
                name="generate_report",
                description="Generate investigation report",
                tool="internal",
                required=True,
            ),
        ]

    def _execute_step(self, step: WorkflowStep, context: WorkflowContext) -> StepResult:
        if step.name == "parse_logs":
            return self._parse_logs(context)
        elif step.name == "detect_attacks":
            return self._detect_attacks(context)
        elif step.name == "detect_bruteforce":
            return self._detect_bruteforce(context)
        elif step.name == "detect_scanners":
            return self._detect_scanners(context)
        elif step.name == "extract_attackers":
            return self._extract_attackers(context)
        elif step.name == "check_ips":
            return self._check_ips(context)
        elif step.name == "generate_report":
            return self._generate_report(context)
        else:
            return StepResult(step_name=step.name, success=False, error="Unknown step")

    def _parse_logs(self, context: WorkflowContext) -> StepResult:
        """Parse log file"""
        try:
            from vlair.tools.log_analyzer import LogAnalyzer

            analyzer = LogAnalyzer(verbose=self.verbose)
            result = analyzer.analyze(context.input_value)

            context.add_tool_result("log_analyzer", result)
            context.data["log_result"] = result

            stats = result.get("statistics", {})
            self._log(f"  Analyzed {stats.get('total_entries', 0)} log entries")

            return StepResult(step_name="parse_logs", success=True, data=result)

        except ImportError:
            return StepResult(
                step_name="parse_logs", success=False, error="Log analyzer not available"
            )
        except Exception as e:
            return StepResult(step_name="parse_logs", success=False, error=str(e))

    def _detect_attacks(self, context: WorkflowContext) -> StepResult:
        """Detect web attacks"""
        log_result = context.data.get("log_result", {})
        threats = log_result.get("threats", {})

        attack_counts = {}

        # SQL Injection
        sqli = threats.get("sql_injection", [])
        if sqli:
            attack_counts["sql_injection"] = len(sqli)
            context.scorer.add_finding(
                Severity.CRITICAL,
                f"Detected {len(sqli)} SQL injection attempts",
                "log_analyzer",
                {"count": len(sqli), "samples": sqli[:3]},
            )

        # XSS
        xss = threats.get("xss", [])
        if xss:
            attack_counts["xss"] = len(xss)
            context.scorer.add_finding(
                Severity.HIGH,
                f"Detected {len(xss)} XSS attempts",
                "log_analyzer",
                {"count": len(xss), "samples": xss[:3]},
            )

        # Path Traversal
        traversal = threats.get("path_traversal", [])
        if traversal:
            attack_counts["path_traversal"] = len(traversal)
            context.scorer.add_finding(
                Severity.HIGH,
                f"Detected {len(traversal)} path traversal attempts",
                "log_analyzer",
                {"count": len(traversal), "samples": traversal[:3]},
            )

        # Command Injection
        cmd_injection = threats.get("command_injection", [])
        if cmd_injection:
            attack_counts["command_injection"] = len(cmd_injection)
            context.scorer.add_finding(
                Severity.CRITICAL,
                f"Detected {len(cmd_injection)} command injection attempts",
                "log_analyzer",
                {"count": len(cmd_injection), "samples": cmd_injection[:3]},
            )

        context.data["attack_counts"] = attack_counts
        return StepResult(step_name="detect_attacks", success=True, data=attack_counts)

    def _detect_bruteforce(self, context: WorkflowContext) -> StepResult:
        """Detect brute force attempts"""
        log_result = context.data.get("log_result", {})
        threats = log_result.get("threats", {})

        brute_force = threats.get("brute_force", [])
        if brute_force:
            context.scorer.add_finding(
                Severity.MEDIUM,
                f"Detected brute force activity from {len(brute_force)} sources",
                "log_analyzer",
                {"sources": brute_force[:5]},
            )

            # Add brute force IPs to attacker list
            for entry in brute_force:
                if isinstance(entry, dict) and entry.get("ip"):
                    context.add_iocs("ips", [entry["ip"]])
                elif isinstance(entry, str):
                    context.add_iocs("ips", [entry])

        context.data["brute_force_count"] = len(brute_force)
        return StepResult(
            step_name="detect_bruteforce", success=True, data={"count": len(brute_force)}
        )

    def _detect_scanners(self, context: WorkflowContext) -> StepResult:
        """Detect scanner activity"""
        log_result = context.data.get("log_result", {})
        threats = log_result.get("threats", {})

        scanners = threats.get("scanners", [])
        if scanners:
            context.scorer.add_finding(
                Severity.LOW,
                f"Detected scanner activity from {len(scanners)} sources",
                "log_analyzer",
                {"sources": scanners[:5]},
            )

            # Add scanner IPs
            for entry in scanners:
                if isinstance(entry, dict) and entry.get("ip"):
                    context.add_iocs("ips", [entry["ip"]])

        context.data["scanner_count"] = len(scanners)
        return StepResult(step_name="detect_scanners", success=True, data={"count": len(scanners)})

    def _extract_attackers(self, context: WorkflowContext) -> StepResult:
        """Extract unique attacker IPs"""
        log_result = context.data.get("log_result", {})
        threats = log_result.get("threats", {})

        attacker_ips = set()

        # Collect IPs from all threat categories
        for threat_type, entries in threats.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and entry.get("ip"):
                        attacker_ips.add(entry["ip"])
                    elif isinstance(entry, str):
                        # Check if it looks like an IP
                        if entry.count(".") == 3:
                            attacker_ips.add(entry)

        context.add_iocs("ips", list(attacker_ips))
        context.data["attacker_ips"] = list(attacker_ips)

        self._log(f"  Found {len(attacker_ips)} unique attacker IPs")

        return StepResult(
            step_name="extract_attackers", success=True, data={"count": len(attacker_ips)}
        )

    def _check_ips(self, context: WorkflowContext) -> StepResult:
        """Check attacker IPs against threat intelligence"""
        ips = context.data.get("attacker_ips", [])[:10]  # Limit to 10

        if not ips:
            return StepResult(
                step_name="check_ips",
                success=True,
                data={"checked": 0, "message": "No IPs to check"},
            )

        try:
            from vlair.tools.domain_ip_intel import DomainIPIntelligence as DomainIPIntel

            intel = DomainIPIntel(verbose=self.verbose)

            results = {"checked": 0, "known_malicious": 0}

            for ip in ips:
                result = intel.lookup(ip)
                results["checked"] += 1

                if result.get("verdict") == "malicious":
                    results["known_malicious"] += 1
                    context.scorer.add_finding(
                        Severity.HIGH,
                        f"Attacker IP is known malicious: {ip}",
                        "domain_intel",
                        result,
                    )

            context.data["ip_check_results"] = results
            return StepResult(step_name="check_ips", success=True, data=results)

        except Exception as e:
            return StepResult(step_name="check_ips", success=False, error=str(e))

    def _generate_report(self, context: WorkflowContext) -> StepResult:
        """Generate investigation report"""
        summary = context.scorer.get_summary()
        log_result = context.data.get("log_result", {})

        # Calculate attack summary
        attack_counts = context.data.get("attack_counts", {})
        total_attacks = sum(attack_counts.values())

        recommendations = []

        if summary["risk_score"] >= 70:
            recommendations.extend(
                [
                    "INCIDENT: Active attack detected - initiate incident response",
                    "Block identified attacker IPs at firewall/WAF",
                    "Review affected endpoints for compromise",
                    "Check for successful exploitation",
                    "Preserve logs for forensic analysis",
                ]
            )
        elif summary["risk_score"] >= 40:
            recommendations.extend(
                [
                    "Add identified IPs to monitoring watchlist",
                    "Review WAF rules for attack patterns detected",
                    "Increase logging verbosity temporarily",
                ]
            )
        else:
            recommendations.append("Normal scanning activity detected - continue monitoring")

        # Add specific recommendations based on attack types
        if attack_counts.get("sql_injection", 0) > 0:
            recommendations.append("Review database access logs for successful queries")
        if attack_counts.get("path_traversal", 0) > 0:
            recommendations.append("Verify file access permissions are properly configured")
        if attack_counts.get("command_injection", 0) > 0:
            recommendations.append("Check for unauthorized process execution")

        return StepResult(
            step_name="generate_report",
            success=True,
            data={
                "total_entries": log_result.get("statistics", {}).get("total_entries", 0),
                "total_attacks": total_attacks,
                "attack_breakdown": attack_counts,
                "unique_attackers": len(context.data.get("attacker_ips", [])),
                "known_malicious_ips": context.data.get("ip_check_results", {}).get(
                    "known_malicious", 0
                ),
                "risk_score": summary["risk_score"],
                "verdict": summary["verdict"],
                "recommendations": recommendations,
            },
        )
