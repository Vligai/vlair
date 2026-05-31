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

    def __init__(self, verbose: bool = False, sigma_rules=None):
        self._sigma_rules = sigma_rules  # None → use builtin pack; "builtin" or path → override
        super().__init__(verbose=verbose)

    def _define_steps(self):
        self.steps = [
            WorkflowStep(
                name="parse_logs",
                description="Parse and analyze log file",
                tool="log_analyzer",
                required=True,
            ),
            WorkflowStep(
                name="sigma_evaluation",
                description="Evaluate Sigma rules against log events",
                tool="sigma",
                required=False,
                depends_on=["parse_logs"],
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
        elif step.name == "sigma_evaluation":
            return self._sigma_evaluation(context)
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
        """Parse log file using analyze_file() with Sigma rules."""
        try:
            from vlair.tools.log_analyzer import LogAnalyzer

            sigma_rules = self._sigma_rules if self._sigma_rules is not None else "builtin"

            analyzer = LogAnalyzer(verbose=self.verbose)
            result = analyzer.analyze_file(context.input_value, sigma_rules=sigma_rules)

            context.add_tool_result("log_analyzer", result)
            context.data["log_result"] = result

            meta = result.get("metadata", {})
            self._log(f"  Analyzed {meta.get('total_entries', 0)} log entries")
            if "sigma_rules_evaluated" in meta:
                self._log(f"  Sigma: {meta['sigma_rules_evaluated']} rules evaluated")

            return StepResult(step_name="parse_logs", success=True, data=result)

        except ImportError:
            return StepResult(step_name="parse_logs", success=False, error="Log analyzer not available")
        except Exception as e:
            return StepResult(step_name="parse_logs", success=False, error=str(e))

    def _sigma_evaluation(self, context: WorkflowContext) -> StepResult:
        """Process Sigma matches from log_result and add to scorer."""
        log_result = context.data.get("log_result", {})
        sigma_alerts = [a for a in log_result.get("alerts", []) if a.get("source") == "sigma"]

        if not sigma_alerts:
            return StepResult(step_name="sigma_evaluation", success=True, data={"sigma_matches": 0})

        # Group by level for max-of-levels scoring
        by_level: Dict[str, list] = {}
        for alert in sigma_alerts:
            level = (alert.get("level") or "medium").lower()
            by_level.setdefault(level, []).append(alert)

        _level_to_sev = {
            "informational": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        for level, alerts in by_level.items():
            severity = _level_to_sev.get(level, Severity.MEDIUM)
            sample = alerts[0]
            context.scorer.add_finding(
                severity,
                f"Sigma [{level}]: {sample.get('rule_name', 'Unknown')} (+{len(alerts) - 1} more at this level)",
                "sigma",
                {"sigma_level": level, "match_count": len(alerts), "rule_link": sample.get("rule_link", "")},
            )

        context.data["sigma_matches"] = sigma_alerts
        self._log(f"  {len(sigma_alerts)} Sigma match(es) across {len(by_level)} level(s)")

        return StepResult(
            step_name="sigma_evaluation",
            success=True,
            data={"sigma_matches": len(sigma_alerts), "levels": list(by_level.keys())},
        )

    def _detect_attacks(self, context: WorkflowContext) -> StepResult:
        """Detect web attacks from pattern alerts."""
        log_result = context.data.get("log_result", {})
        pattern_alerts = [a for a in log_result.get("alerts", []) if a.get("source") == "pattern"]

        attack_counts: Dict[str, Any] = {}

        _type_to_sev = {
            "sql_injection": Severity.CRITICAL,
            "xss": Severity.HIGH,
            "path_traversal": Severity.HIGH,
            "scanner_detected": Severity.MEDIUM,
        }

        for alert in pattern_alerts:
            atype = alert.get("type", "unknown")
            if atype in _type_to_sev:
                attack_counts[atype] = attack_counts.get(atype, 0) + 1

        for atype, count in attack_counts.items():
            severity = _type_to_sev.get(atype, Severity.MEDIUM)
            context.scorer.add_finding(
                severity,
                f"Detected {count} {atype.replace('_', ' ')} attempt(s)",
                "log_analyzer",
                {"count": count, "type": atype},
            )

        context.data["attack_counts"] = attack_counts
        return StepResult(step_name="detect_attacks", success=True, data=attack_counts)

    def _detect_bruteforce(self, context: WorkflowContext) -> StepResult:
        """Detect brute force attempts from pattern alerts."""
        log_result = context.data.get("log_result", {})
        bf_alerts = [
            a for a in log_result.get("alerts", []) if a.get("source") == "pattern" and a.get("type") == "brute_force_attempt"
        ]

        if bf_alerts:
            context.scorer.add_finding(
                Severity.MEDIUM,
                f"Detected brute force activity ({len(bf_alerts)} event(s))",
                "log_analyzer",
                {"count": len(bf_alerts)},
            )
            for alert in bf_alerts:
                ip = alert.get("source_ip")
                if ip:
                    context.add_iocs("ips", [ip])

        context.data["brute_force_count"] = len(bf_alerts)
        return StepResult(step_name="detect_bruteforce", success=True, data={"count": len(bf_alerts)})

    def _detect_scanners(self, context: WorkflowContext) -> StepResult:
        """Detect scanner activity from pattern alerts."""
        log_result = context.data.get("log_result", {})
        scanner_alerts = [
            a for a in log_result.get("alerts", []) if a.get("source") == "pattern" and a.get("type") == "scanner_detected"
        ]

        if scanner_alerts:
            context.scorer.add_finding(
                Severity.LOW,
                f"Detected scanner activity ({len(scanner_alerts)} event(s))",
                "log_analyzer",
                {"count": len(scanner_alerts)},
            )
            for alert in scanner_alerts:
                ip = alert.get("source_ip")
                if ip:
                    context.add_iocs("ips", [ip])

        context.data["scanner_count"] = len(scanner_alerts)
        return StepResult(step_name="detect_scanners", success=True, data={"count": len(scanner_alerts)})

    def _extract_attackers(self, context: WorkflowContext) -> StepResult:
        """Extract unique attacker IPs from alert source_ip fields."""
        log_result = context.data.get("log_result", {})
        attacker_ips: set = set()

        for alert in log_result.get("alerts", []):
            ip = alert.get("source_ip")
            if ip:
                attacker_ips.add(ip)
            # Sigma match matched_event may also carry source_ip
            matched = alert.get("matched_event", {})
            if isinstance(matched, dict):
                ip2 = matched.get("source_ip")
                if ip2:
                    attacker_ips.add(ip2)

        context.add_iocs("ips", list(attacker_ips))
        context.data["attacker_ips"] = list(attacker_ips)

        self._log(f"  Found {len(attacker_ips)} unique attacker IPs")

        return StepResult(step_name="extract_attackers", success=True, data={"count": len(attacker_ips)})

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

        # Sigma match summary for report (task 6.3)
        sigma_matches = context.data.get("sigma_matches", [])
        sigma_summary = []
        for m in sigma_matches[:20]:
            entry = {
                "rule_name": m.get("rule_name", "Unknown"),
                "level": m.get("level", "medium"),
                "match_count": m.get("match_count", 1),
                "mitre_attack": m.get("mitre_attack", []),
            }
            if m.get("rule_link"):
                entry["rule_link"] = m["rule_link"]
            sigma_summary.append(entry)

        report_data: Dict[str, Any] = {
            "total_entries": log_result.get("metadata", {}).get("total_entries", 0),
            "total_attacks": total_attacks,
            "attack_breakdown": attack_counts,
            "unique_attackers": len(context.data.get("attacker_ips", [])),
            "known_malicious_ips": context.data.get("ip_check_results", {}).get("known_malicious", 0),
            "sigma_matches": sigma_summary,
            "risk_score": summary["risk_score"],
            "verdict": summary["verdict"],
            "recommendations": recommendations,
        }
        if sigma_summary:
            report_data["sigma_docs"] = "docs/SIGMA.md"

        return StepResult(
            step_name="generate_report",
            success=True,
            data=report_data,
        )
