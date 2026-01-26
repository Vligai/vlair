#!/usr/bin/env python3
"""
Interactive Investigation Mode
Guided Q&A for security investigations
Part of SecOps Helper Operationalization (Phase 5)
"""

import sys
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.analyzer import Analyzer
from core.reporter import Reporter, Colors
from core.workflow import WorkflowRegistry


class ProgressBar:
    """Simple progress bar for terminal output"""

    def __init__(self, total: int = 100, width: int = 40):
        self.total = total
        self.width = width
        self.current = 0

    def update(self, value: int, message: str = ""):
        """Update progress bar"""
        self.current = min(value, self.total)
        filled = int(self.width * self.current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)
        percent = int(100 * self.current / self.total)

        # Clear line and print progress
        sys.stdout.write(f"\r[{bar}] {percent}% {message}")
        sys.stdout.flush()

        if self.current >= self.total:
            print()  # New line when complete

    def complete(self, message: str = "Complete"):
        """Mark progress as complete"""
        self.update(self.total, message)


class InteractiveInvestigation:
    """
    Interactive investigation mode.
    Guides users through security investigations with menus and prompts.
    """

    INVESTIGATION_TYPES = [
        {
            "id": "email",
            "name": "Suspicious email",
            "description": "Analyze a potentially malicious email (.eml file)",
            "workflow": "phishing-email",
            "input_prompt": "Enter the path to the email file (.eml):",
            "file_required": True,
        },
        {
            "id": "file",
            "name": "Suspicious file/attachment",
            "description": "Analyze a potentially malicious file",
            "workflow": "malware-triage",
            "input_prompt": "Enter the path to the file:",
            "file_required": True,
        },
        {
            "id": "indicator",
            "name": "Suspicious domain/IP/URL/hash",
            "description": "Check a single indicator against threat intelligence",
            "workflow": None,  # Use analyzer directly
            "input_prompt": "Enter the indicator (domain, IP, URL, or hash):",
            "file_required": False,
        },
        {
            "id": "pcap",
            "name": "Network traffic (PCAP)",
            "description": "Analyze network capture for threats",
            "workflow": "network-forensics",
            "input_prompt": "Enter the path to the PCAP file:",
            "file_required": True,
        },
        {
            "id": "log",
            "name": "Log files",
            "description": "Analyze security logs for attacks",
            "workflow": "log-investigation",
            "input_prompt": "Enter the path to the log file:",
            "file_required": True,
        },
        {
            "id": "iocs",
            "name": "IOC list",
            "description": "Check a list of indicators against threat intelligence",
            "workflow": "ioc-hunt",
            "input_prompt": "Enter the path to the IOC list file:",
            "file_required": True,
        },
    ]

    def __init__(self):
        self.analyzer = Analyzer(verbose=False)
        self.reporter = Reporter(use_colors=True)
        self._init_workflows()

    def _init_workflows(self):
        """Initialize workflow registry"""
        try:
            from workflows import (
                PhishingEmailWorkflow,
                MalwareTriageWorkflow,
                IOCHuntWorkflow,
                NetworkForensicsWorkflow,
                LogInvestigationWorkflow,
            )
        except ImportError:
            pass

    def run(self):
        """Run the interactive investigation"""
        self._print_header()

        while True:
            try:
                # Show investigation type menu
                inv_type = self._select_investigation_type()
                if inv_type is None:
                    break

                # Get input from user
                input_value = self._get_input(inv_type)
                if input_value is None:
                    continue

                # Run analysis
                result = self._run_analysis(inv_type, input_value)
                if result is None:
                    continue

                # Show results
                self._show_results(result, inv_type)

                # Post-analysis actions
                if not self._post_analysis_menu(result):
                    break

            except KeyboardInterrupt:
                print("\n")
                break

        self._print_goodbye()

    def _print_header(self):
        """Print welcome header"""
        print()
        print(f"{Colors.BOLD}{'=' * 65}{Colors.RESET}")
        print(f"{Colors.BOLD}  SecOps Helper - Interactive Investigation Mode{Colors.RESET}")
        print(f"{'=' * 65}")
        print()
        print("  This mode will guide you through a security investigation.")
        print("  Answer the prompts to analyze suspicious artifacts.")
        print()
        print(f"  {Colors.DIM}Press Ctrl+C at any time to exit{Colors.RESET}")
        print()

    def _print_goodbye(self):
        """Print goodbye message"""
        print()
        print(f"{Colors.DIM}Thank you for using SecOps Helper. Stay secure!{Colors.RESET}")
        print()

    def _select_investigation_type(self) -> Optional[Dict]:
        """Show menu to select investigation type"""
        print(f"{Colors.BOLD}What are you investigating?{Colors.RESET}")
        print()

        for i, inv_type in enumerate(self.INVESTIGATION_TYPES, 1):
            print(f"  [{i}] {inv_type['name']}")
            print(f"      {Colors.DIM}{inv_type['description']}{Colors.RESET}")

        print()
        print(f"  [0] Exit")
        print()

        while True:
            try:
                choice = input(f"{Colors.CYAN}> {Colors.RESET}").strip()

                if choice == "0" or choice.lower() in ["exit", "quit", "q"]:
                    return None

                idx = int(choice) - 1
                if 0 <= idx < len(self.INVESTIGATION_TYPES):
                    print()
                    return self.INVESTIGATION_TYPES[idx]

                print(
                    f"{Colors.RED}Invalid choice. Please enter 1-{len(self.INVESTIGATION_TYPES)} or 0 to exit.{Colors.RESET}"
                )

            except ValueError:
                print(f"{Colors.RED}Please enter a number.{Colors.RESET}")
            except EOFError:
                return None

    def _get_input(self, inv_type: Dict) -> Optional[str]:
        """Get input from user based on investigation type"""
        print(f"{Colors.BOLD}{inv_type['input_prompt']}{Colors.RESET}")
        print()

        while True:
            try:
                value = input(f"{Colors.CYAN}> {Colors.RESET}").strip()

                if not value:
                    print(f"{Colors.YELLOW}Please enter a value.{Colors.RESET}")
                    continue

                # Handle quoted paths
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                # Validate file exists if required
                if inv_type["file_required"]:
                    path = Path(value).expanduser()
                    if not path.exists():
                        print(f"{Colors.RED}File not found: {value}{Colors.RESET}")
                        print("Please enter a valid file path.")
                        continue
                    value = str(path.absolute())

                print()
                return value

            except EOFError:
                return None
            except KeyboardInterrupt:
                print()
                return None

    def _run_analysis(self, inv_type: Dict, input_value: str) -> Optional[Dict]:
        """Run the analysis and show progress"""
        workflow_name = inv_type["workflow"]

        print(f"{Colors.BOLD}Running analysis...{Colors.RESET}")
        print()

        progress = ProgressBar()

        try:
            if workflow_name:
                # Run workflow
                workflow_class = WorkflowRegistry.get(workflow_name)
                if not workflow_class:
                    print(f"{Colors.RED}Workflow '{workflow_name}' not available.{Colors.RESET}")
                    return None

                workflow = workflow_class(verbose=False)
                total_steps = len(workflow.steps)

                # Simulate progress during workflow execution
                progress.update(10, "Initializing...")

                result = workflow.execute(input_value, inv_type["id"])

                # Update progress based on completed steps
                steps_done = result.get("steps_completed", 0)
                progress.update(10 + int(80 * steps_done / total_steps), f"Step {steps_done}/{total_steps}")

                progress.complete("Analysis complete")

                return {"type": "workflow", "workflow_name": workflow_name, "result": result}

            else:
                # Run direct analysis
                progress.update(20, "Detecting input type...")

                result = self.analyzer.analyze(input_value)

                progress.update(100, "Complete")
                progress.complete("Analysis complete")

                return {"type": "analyze", "result": result}

        except Exception as e:
            print(f"\n{Colors.RED}Error during analysis: {e}{Colors.RESET}")
            return None

    def _show_results(self, analysis_result: Dict, inv_type: Dict):
        """Display analysis results"""
        print()
        print(f"{'=' * 65}")
        print(f"{Colors.BOLD}                    ANALYSIS COMPLETE{Colors.RESET}")
        print(f"{'=' * 65}")
        print()

        if analysis_result["type"] == "workflow":
            result = analysis_result["result"]
            scorer = result["scorer"]
            summary = scorer.get_summary()
        else:
            result = analysis_result["result"]
            scorer = result["scorer"]
            summary = scorer.get_summary()

        # Risk score with visual
        score = summary["risk_score"]
        verdict = summary["verdict"]
        verdict_color = self._get_verdict_color(verdict)

        print(f"Risk Score: {self._score_bar(score)} {score}/100 ({self._score_label(score)})")
        print(f"Verdict: {verdict_color}{verdict}{Colors.RESET}")
        print()

        # Key findings
        findings = scorer.get_findings()
        if findings:
            print(f"{Colors.BOLD}Key Findings:{Colors.RESET}")
            for finding in findings[:8]:
                icon = self._severity_icon(finding["severity"])
                print(f"  {icon} {finding['message']}")
            if len(findings) > 8:
                print(f"  {Colors.DIM}... and {len(findings) - 8} more findings{Colors.RESET}")
            print()

        # IOCs summary
        iocs = result.get("iocs", {})
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        if total_iocs > 0:
            print(f"{Colors.BOLD}Extracted IOCs:{Colors.RESET} {total_iocs} indicators found")
            for ioc_type, values in iocs.items():
                if values:
                    print(f"  - {ioc_type.capitalize()}: {len(values)}")
            print()

        # Recommendations
        recommendations = scorer.get_recommendations()
        if recommendations:
            print(f"{Colors.BOLD}Recommended Actions:{Colors.RESET}")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"  {i}. {rec}")
            print()

    def _post_analysis_menu(self, analysis_result: Dict) -> bool:
        """Show post-analysis action menu. Returns True to continue, False to exit."""
        print(f"{Colors.BOLD}What would you like to do next?{Colors.RESET}")
        print()
        print("  [1] Export IOCs to file")
        print("  [2] View detailed results (JSON)")
        print("  [3] Start new investigation")
        print("  [4] Exit")
        print()

        while True:
            try:
                choice = input(f"{Colors.CYAN}> {Colors.RESET}").strip()

                if choice == "1":
                    self._export_iocs(analysis_result)
                    return True
                elif choice == "2":
                    self._show_json_results(analysis_result)
                    return True
                elif choice == "3":
                    print()
                    return True
                elif choice == "4" or choice.lower() in ["exit", "quit", "q"]:
                    return False
                else:
                    print(f"{Colors.RED}Please enter 1-4.{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                return False

    def _export_iocs(self, analysis_result: Dict):
        """Export IOCs to a file"""
        if analysis_result["type"] == "workflow":
            iocs = analysis_result["result"].get("iocs", {})
        else:
            iocs = analysis_result["result"].get("iocs", {})

        print()
        print("Enter output file path (or press Enter for 'exported_iocs.txt'):")

        try:
            path = input(f"{Colors.CYAN}> {Colors.RESET}").strip()
            if not path:
                path = "exported_iocs.txt"

            with open(path, "w") as f:
                f.write("# Exported IOCs from SecOps Helper\n")
                f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                for ioc_type, values in iocs.items():
                    if values:
                        f.write(f"# {ioc_type.upper()}\n")
                        for val in values:
                            f.write(f"{val}\n")
                        f.write("\n")

            print(f"{Colors.GREEN}IOCs exported to: {path}{Colors.RESET}")
            print()

        except Exception as e:
            print(f"{Colors.RED}Error exporting IOCs: {e}{Colors.RESET}")
            print()

    def _show_json_results(self, analysis_result: Dict):
        """Show detailed JSON results"""
        import json

        print()
        print(f"{Colors.BOLD}Detailed Results (JSON):{Colors.RESET}")
        print("-" * 65)

        if analysis_result["type"] == "workflow":
            result = analysis_result["result"].copy()
            result["summary"] = result["scorer"].get_summary()
            result["findings"] = result["scorer"].get_findings()
            del result["scorer"]
        else:
            result = analysis_result["result"].copy()
            result["summary"] = result["scorer"].get_summary()
            result["findings"] = result["scorer"].get_findings()
            del result["scorer"]

        print(json.dumps(result, indent=2, default=str))
        print("-" * 65)
        print()

    def _get_verdict_color(self, verdict: str) -> str:
        """Get color for verdict"""
        colors = {
            "MALICIOUS": Colors.RED,
            "SUSPICIOUS": Colors.YELLOW,
            "LOW_RISK": Colors.CYAN,
            "CLEAN": Colors.GREEN,
            "UNKNOWN": Colors.DIM,
        }
        return colors.get(verdict, "")

    def _score_bar(self, score: int) -> str:
        """Create visual score bar"""
        filled = score // 10
        empty = 10 - filled

        if score >= 70:
            color = Colors.RED
        elif score >= 40:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN

        return f"[{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.RESET}]"

    def _score_label(self, score: int) -> str:
        """Get label for score"""
        if score >= 70:
            return f"{Colors.RED}HIGH RISK{Colors.RESET}"
        elif score >= 40:
            return f"{Colors.YELLOW}MEDIUM RISK{Colors.RESET}"
        elif score >= 10:
            return f"{Colors.CYAN}LOW RISK{Colors.RESET}"
        else:
            return f"{Colors.GREEN}MINIMAL{Colors.RESET}"

    def _severity_icon(self, severity: str) -> str:
        """Get icon for severity"""
        icons = {
            "critical": f"{Colors.RED}[!]{Colors.RESET}",
            "high": f"{Colors.YELLOW}[!]{Colors.RESET}",
            "medium": f"{Colors.CYAN}[*]{Colors.RESET}",
            "low": f"{Colors.DIM}[-]{Colors.RESET}",
            "info": f"{Colors.DIM}[i]{Colors.RESET}",
        }
        return icons.get(severity, "[?]")


def main():
    """Run interactive investigation"""
    investigation = InteractiveInvestigation()
    investigation.run()


if __name__ == "__main__":
    main()
