#!/usr/bin/env python3
"""
Reporter - Format analysis results for output
Part of SecOps Helper Operationalization (Phase 5)
"""

import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

from .scorer import RiskScorer, Verdict, Severity


class Colors:
    """ANSI color codes for terminal output"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)"""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RESET = ""

    @classmethod
    def enable(cls):
        """Re-enable colors"""
        cls.RED = "\033[91m"
        cls.GREEN = "\033[92m"
        cls.YELLOW = "\033[93m"
        cls.BLUE = "\033[94m"
        cls.MAGENTA = "\033[95m"
        cls.CYAN = "\033[96m"
        cls.WHITE = "\033[97m"
        cls.BOLD = "\033[1m"
        cls.DIM = "\033[2m"
        cls.RESET = "\033[0m"


class Reporter:
    """
    Format and output analysis results.
    Supports console (human-readable) and JSON output.
    """

    def __init__(self, use_colors: bool = True):
        """
        Initialize reporter.

        Args:
            use_colors: Whether to use ANSI colors in output
        """
        self.use_colors = use_colors and sys.stdout.isatty()
        if not self.use_colors:
            Colors.disable()

    def format_console(
        self,
        input_value: str,
        input_type: str,
        scorer: RiskScorer,
        iocs: Dict[str, List],
        tool_results: Dict[str, Any],
    ) -> str:
        """
        Format results for console output.

        Args:
            input_value: The original input
            input_type: Detected input type
            scorer: RiskScorer with findings
            iocs: Extracted IOCs
            tool_results: Raw results from each tool

        Returns:
            Formatted string for console display
        """
        summary = scorer.get_summary()
        score = summary["risk_score"]
        verdict = summary["verdict"]
        findings = scorer.get_findings()
        recommendations = scorer.get_recommendations()

        lines = []

        # Header
        lines.append(self._header_line())
        lines.append(f" {Colors.BOLD}SecOps Helper - Analysis Report{Colors.RESET}")
        lines.append(self._header_line())
        lines.append("")

        # Input info
        lines.append(f"Input: {Colors.CYAN}{input_value}{Colors.RESET}")
        lines.append(f"Type: {input_type}")
        lines.append(f"Analyzed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append("")

        # Verdict box
        lines.append(self._separator_line())
        verdict_color = self._get_verdict_color(verdict)
        score_bar = self._score_bar(score)
        lines.append(
            f" {Colors.BOLD}VERDICT: {verdict_color}{verdict}{Colors.RESET}"
            f"                           Risk Score: {score_bar} {score}/100"
        )
        lines.append(self._separator_line())
        lines.append("")

        # Key findings
        if findings:
            lines.append(f"{Colors.BOLD}Key Findings:{Colors.RESET}")
            for finding in findings[:10]:  # Limit to top 10
                icon = self._severity_icon(finding["severity"])
                lines.append(f"  {icon} {finding['message']}")
            if len(findings) > 10:
                lines.append(
                    f"  {Colors.DIM}... and {len(findings) - 10} more findings{Colors.RESET}"
                )
            lines.append("")

        # Extracted IOCs
        if any(iocs.values()):
            lines.append(f"{Colors.BOLD}Extracted IOCs:{Colors.RESET}")
            for ioc_type, values in iocs.items():
                if values:
                    # Show first few, indicate total
                    display_vals = values[:3]
                    verdict_tags = self._get_ioc_verdicts(display_vals, tool_results)

                    formatted = []
                    for val, tag in zip(display_vals, verdict_tags):
                        formatted.append(f"{self._defang(val)} {tag}")

                    remaining = len(values) - len(display_vals)
                    suffix = f" (+{remaining} more)" if remaining > 0 else ""

                    lines.append(
                        f"  {ioc_type.capitalize()} ({len(values)}): "
                        f"{', '.join(formatted)}{suffix}"
                    )
            lines.append("")

        # Recommendations
        if recommendations:
            lines.append(f"{Colors.BOLD}Recommended Actions:{Colors.RESET}")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        # Footer
        lines.append(self._separator_line())
        lines.append(
            f"{Colors.DIM}Use --verbose for detailed results | --json for machine-readable output{Colors.RESET}"
        )
        lines.append(self._header_line())

        return "\n".join(lines)

    def format_json(
        self,
        input_value: str,
        input_type: str,
        scorer: RiskScorer,
        iocs: Dict[str, List],
        tool_results: Dict[str, Any],
    ) -> str:
        """
        Format results as JSON.

        Args:
            input_value: The original input
            input_type: Detected input type
            scorer: RiskScorer with findings
            iocs: Extracted IOCs
            tool_results: Raw results from each tool

        Returns:
            JSON string
        """
        summary = scorer.get_summary()

        output = {
            "input": input_value,
            "type": input_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "verdict": summary["verdict"],
            "risk_score": summary["risk_score"],
            "confidence": summary["confidence"],
            "findings": scorer.get_findings(),
            "iocs": iocs,
            "recommendations": scorer.get_recommendations(),
            "tool_results": tool_results,
        }

        return json.dumps(output, indent=2, default=str)

    def format_quiet(self, scorer: RiskScorer) -> str:
        """
        Format minimal output for scripting.

        Returns:
            Single line: VERDICT SCORE
        """
        summary = scorer.get_summary()
        return f"{summary['verdict']} {summary['risk_score']}"

    def format_verbose(
        self,
        input_value: str,
        input_type: str,
        scorer: RiskScorer,
        iocs: Dict[str, List],
        tool_results: Dict[str, Any],
    ) -> str:
        """
        Format detailed output with full tool results.
        """
        lines = []

        # Start with standard console output
        lines.append(self.format_console(input_value, input_type, scorer, iocs, tool_results))
        lines.append("")

        # Add detailed tool results
        lines.append(f"{Colors.BOLD}Detailed Tool Results:{Colors.RESET}")
        lines.append(self._header_line())

        for tool_name, result in tool_results.items():
            lines.append(f"\n{Colors.CYAN}[{tool_name}]{Colors.RESET}")
            if isinstance(result, dict):
                lines.append(json.dumps(result, indent=2, default=str))
            else:
                lines.append(str(result))

        return "\n".join(lines)

    def _header_line(self) -> str:
        """Create a header line."""
        return "=" * 65

    def _separator_line(self) -> str:
        """Create a separator line."""
        return "-" * 65

    def _get_verdict_color(self, verdict: str) -> str:
        """Get color for verdict."""
        colors = {
            "MALICIOUS": Colors.RED,
            "SUSPICIOUS": Colors.YELLOW,
            "LOW_RISK": Colors.CYAN,
            "CLEAN": Colors.GREEN,
            "UNKNOWN": Colors.DIM,
        }
        return colors.get(verdict, "")

    def _score_bar(self, score: int) -> str:
        """Create a visual score bar."""
        filled = score // 10
        empty = 10 - filled

        if score >= 70:
            color = Colors.RED
        elif score >= 40:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN

        bar = f"{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.RESET}"
        return f"[{bar}]"

    def _severity_icon(self, severity: str) -> str:
        """Get icon for severity level."""
        icons = {
            "critical": f"{Colors.RED}[!]{Colors.RESET}",
            "high": f"{Colors.YELLOW}[!]{Colors.RESET}",
            "medium": f"{Colors.CYAN}[*]{Colors.RESET}",
            "low": f"{Colors.DIM}[-]{Colors.RESET}",
            "info": f"{Colors.DIM}[i]{Colors.RESET}",
        }
        return icons.get(severity, "[?]")

    def _defang(self, value: str) -> str:
        """Defang IOCs for safe display."""
        # Defang URLs
        value = value.replace("http://", "hxxp://")
        value = value.replace("https://", "hxxps://")

        # Defang domains/IPs
        value = value.replace(".", "[.]")

        return value

    def _get_ioc_verdicts(self, iocs: List[str], tool_results: Dict[str, Any]) -> List[str]:
        """Get verdict tags for IOCs based on tool results."""
        verdicts = []

        for ioc in iocs:
            verdict_tag = ""

            # Check hash results
            hash_results = tool_results.get("hash_lookup", {})
            if isinstance(hash_results, dict):
                for result in hash_results.get("results", [hash_results]):
                    if result.get("hash", "").lower() == ioc.lower():
                        v = result.get("verdict", "")
                        if v:
                            color = self._get_verdict_color(v.upper())
                            verdict_tag = f"{color}[{v.upper()}]{Colors.RESET}"
                            break

            # Check URL results
            url_results = tool_results.get("url_analyzer", {})
            if isinstance(url_results, dict) and ioc in str(url_results):
                v = url_results.get("verdict", "")
                if v:
                    color = self._get_verdict_color(v.upper())
                    verdict_tag = f"{color}[{v.upper()}]{Colors.RESET}"

            # Check domain/IP results
            intel_results = tool_results.get("domain_intel", {})
            if isinstance(intel_results, dict):
                for result in intel_results.get("results", [intel_results]):
                    if result.get("indicator", "") == ioc:
                        v = result.get("verdict", "")
                        if v:
                            color = self._get_verdict_color(v.upper())
                            verdict_tag = f"{color}[{v.upper()}]{Colors.RESET}"
                            break

            verdicts.append(verdict_tag)

        return verdicts

    def get_exit_code(self, scorer: RiskScorer) -> int:
        """
        Get appropriate exit code based on verdict.

        Returns:
            0 = Clean/Unknown, 1 = Suspicious/Low Risk, 2 = Malicious, 3 = Error
        """
        summary = scorer.get_summary()
        verdict = summary["verdict"]

        if verdict == "MALICIOUS":
            return 2
        elif verdict in ["SUSPICIOUS", "LOW_RISK"]:
            return 1
        else:
            return 0


def main():
    """Test the reporter."""
    from .scorer import RiskScorer, Severity

    # Create test data
    scorer = RiskScorer()
    scorer.add_finding(
        Severity.CRITICAL, "Hash detected as malicious by 45/70 AV engines", "hash_lookup"
    )
    scorer.add_finding(Severity.HIGH, "SPF validation failed - sender may be spoofed", "eml_parser")
    scorer.add_finding(Severity.MEDIUM, "Script was obfuscated (2 layers)", "deobfuscator")

    iocs = {
        "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        "domains": ["evil.com", "phishing.net"],
        "urls": ["http://evil.com/malware.exe"],
        "ips": ["192.168.1.100"],
    }

    tool_results = {
        "hash_lookup": {"verdict": "MALICIOUS"},
        "eml_parser": {"authentication": {"spf": {"result": "fail"}}},
    }

    reporter = Reporter()
    print(reporter.format_console("test.eml", "email", scorer, iocs, tool_results))


if __name__ == "__main__":
    main()
