#!/usr/bin/env python3
"""
vlair - Central Control System
A unified security operations toolkit with automatic tool discovery and management.

Usage:
    vlair shell                # Interactive shell (REPL)
    vlair                      # Tool-browser menu
    vlair analyze <input>      # Smart analyze (auto-detect input type)
    vlair check <type> <value> # Quick indicator lookup
    vlair workflow <name> <in> # Run pre-built investigation workflow
    vlair investigate          # Interactive guided investigation
    vlair status               # Show system status dashboard
    vlair list                 # List all available tools
    vlair <tool> [args]        # Run a specific tool
    vlair info <tool>          # Get detailed info about a tool
    vlair search <keyword>     # Search for tools by keyword
"""

import sys
import os
import json
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse

from vlair.tools import get_tool_registry

# ---------------------------------------------------------------------------
# AI assessment formatter (used by the analyze command)
# ---------------------------------------------------------------------------


def _format_ai_assessment(ai: dict) -> str:
    """Render a ThreatSummarizer result as a human-readable console block."""
    lines = []
    SEP = "=" * 66
    lines.append("")
    lines.append(SEP)
    lines.append("                    AI SECURITY ASSESSMENT")
    lines.append(SEP)

    verdict = ai.get("verdict", "UNKNOWN")
    severity = ai.get("severity", "INFO")
    conf = ai.get("confidence", 0.0)
    conf_pct = f"{int(conf * 100)}%" if conf else "N/A"
    lines.append(f"VERDICT:  {verdict} ({conf_pct} confidence)")
    lines.append(f"SEVERITY: {severity}")

    findings = ai.get("key_findings", [])
    if findings:
        lines.append("")
        lines.append("Key Findings:")
        for f in findings:
            lines.append(f"  \u2022 {f}")

    ctx = ai.get("threat_context", "").strip()
    if ctx:
        lines.append("")
        lines.append("Threat Context:")
        for part in ctx.splitlines():
            lines.append(f"  {part}")

    actions = ai.get("recommended_actions", [])
    if actions:
        lines.append("")
        lines.append("Recommended Actions:")
        last_prio = None
        for act in actions:
            prio = act.get("priority", "").upper().replace("_", "-")
            if prio != last_prio:
                lines.append(f"  {prio}:")
                last_prio = prio
            lines.append(f"    \u2022 {act.get('action', '')}")

    mitre = ai.get("mitre_attack", [])
    if mitre:
        lines.append("")
        lines.append(f"MITRE ATT&CK: {', '.join(mitre)}")

    notes = ai.get("confidence_notes", "").strip()
    if notes:
        lines.append("")
        lines.append("Confidence Notes:")
        for part in notes.splitlines():
            lines.append(f"  {part}")

    meta = ai.get("metadata", {})
    elapsed_ms = meta.get("analysis_time_ms", 0)
    tokens = meta.get("tokens_used", 0)
    cached = meta.get("cached", False)
    model = meta.get("model", "")
    lines.append("")
    lines.append(SEP)
    cache_tag = " | Cache: hit" if cached else " | Cache: miss"
    lines.append(f"AI: {model} | {elapsed_ms}ms | {tokens} tokens{cache_tag}")
    lines.append(SEP)

    return "\n".join(lines)


class ToolDiscovery:
    """Automatically discover and catalog all available tools"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.tools = {}
        self._discover_tools()

    def _discover_tools(self):
        """Scan directories and discover all available tools"""

        # Get tool definitions from the central registry
        tool_definitions = get_tool_registry()

        # Verify and register tools - get the package root
        package_root = Path(__file__).parent.parent  # src/vlair
        for tool_id, metadata in tool_definitions.items():
            # Convert module name to path: vlair.tools.eml_parser -> tools/eml_parser.py
            module_parts = metadata["module"].split(".")
            if len(module_parts) >= 3:
                # Expected format: vlair.tools.tool_name
                relative_path = "/".join(module_parts[1:]) + ".py"
                module_path = package_root / relative_path
            else:
                module_path = self.base_dir / (metadata["module"].replace(".", "/") + ".py")

            if module_path.exists():
                self.tools[tool_id] = metadata
                self.tools[tool_id]["available"] = True
                self.tools[tool_id]["path"] = str(module_path)
            else:
                self.tools[tool_id] = metadata
                self.tools[tool_id]["available"] = False

    def get_tool(self, tool_id: str) -> Optional[Dict]:
        """Get tool metadata by ID"""
        return self.tools.get(tool_id)

    def get_all_tools(self) -> Dict:
        """Get all discovered tools"""
        return self.tools

    def get_by_category(self, category: str) -> List[Tuple[str, Dict]]:
        """Get tools by category"""
        return [(tid, tool) for tid, tool in self.tools.items() if tool["category"] == category]

    def search_tools(self, keyword: str) -> List[Tuple[str, Dict]]:
        """Search tools by keyword"""
        keyword = keyword.lower()
        results = []

        for tool_id, tool in self.tools.items():
            # Search in name, description, and keywords
            if (
                keyword in tool["name"].lower()
                or keyword in tool["description"].lower()
                or any(keyword in kw.lower() for kw in tool["keywords"])
            ):
                results.append((tool_id, tool))

        return results


class ToolManager:
    """Manage and execute tools"""

    def __init__(self, discovery: ToolDiscovery):
        self.discovery = discovery

    def run_tool(self, tool_id: str, args: List[str]):
        """Execute a tool with given arguments"""
        tool = self.discovery.get_tool(tool_id)

        if not tool:
            print(f"Error: Unknown tool '{tool_id}'", file=sys.stderr)
            print(f"Run 'vlair list' to see available tools", file=sys.stderr)
            sys.exit(1)

        if not tool["available"]:
            print(
                f"Error: Tool '{tool_id}' not found at {tool.get('path', 'unknown path')}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Import and run the tool
        try:
            module_name = tool["module"]
            parts = module_name.split(".")

            # Use importlib to import the module from the package
            import importlib

            module = importlib.import_module(module_name)

            # Set up argv for the tool
            tool_script_name = parts[-1] + ".py"
            sys.argv = [tool_script_name] + args

            # Execute
            if hasattr(module, "main"):
                module.main()
            else:
                print(f"Error: Tool module has no main() function", file=sys.stderr)
                sys.exit(1)

        except Exception as e:
            print(f"Error running tool '{tool_id}': {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()
            sys.exit(1)


class InteractiveMenu:
    """Interactive menu system for tool selection"""

    def __init__(self, discovery: ToolDiscovery, manager: ToolManager):
        self.discovery = discovery
        self.manager = manager

    def show_main_menu(self):
        """Display the main menu"""
        print("\n" + "=" * 70)
        print("  vlair - Security Operations Toolkit")
        print("=" * 70)
        print("\nWhat would you like to do?\n")
        print("  1. Browse tools by category")
        print("  2. Search for a tool")
        print("  3. List all tools")
        print("  4. View API key status")
        print("  5. Quick start guide")
        print("  0. Exit")
        print("\n" + "-" * 70)

        choice = input("\nEnter your choice (0-5): ").strip()

        if choice == "1":
            self.browse_by_category()
        elif choice == "2":
            self.search_tools()
        elif choice == "3":
            self.list_all_tools()
        elif choice == "4":
            self.show_api_status()
        elif choice == "5":
            self.show_quick_start()
        elif choice == "0":
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please try again.")
            self.show_main_menu()

    def browse_by_category(self):
        """Browse tools by category"""
        # Get all unique categories
        categories = sorted(
            set(tool["category"] for tool in self.discovery.get_all_tools().values())
        )

        print("\n" + "=" * 70)
        print("  Tool Categories")
        print("=" * 70 + "\n")

        for i, category in enumerate(categories, 1):
            tools_in_category = self.discovery.get_by_category(category)
            print(f"  {i}. {category} ({len(tools_in_category)} tools)")

        print("  0. Back to main menu")
        print("\n" + "-" * 70)

        choice = input("\nSelect category (0-{}): ".format(len(categories))).strip()

        try:
            choice_num = int(choice)
            if choice_num == 0:
                self.show_main_menu()
                return
            elif 1 <= choice_num <= len(categories):
                selected_category = categories[choice_num - 1]
                self.show_category_tools(selected_category)
            else:
                print("\nInvalid choice.")
                self.browse_by_category()
        except ValueError:
            print("\nInvalid input.")
            self.browse_by_category()

    def show_category_tools(self, category: str):
        """Show tools in a specific category"""
        tools = self.discovery.get_by_category(category)

        print("\n" + "=" * 70)
        print(f"  {category} Tools")
        print("=" * 70 + "\n")

        for i, (tool_id, tool) in enumerate(tools, 1):
            status = "✓" if tool["available"] else "✗"
            print(f"  {i}. [{status}] {tool['name']}")
            print(f"      {tool['description']}")
            print()

        print("  i. Get info on a tool")
        print("  0. Back")
        print("\n" + "-" * 70)

        choice = input("\nEnter choice: ").strip()

        if choice == "0":
            self.browse_by_category()
        elif choice.lower() == "i":
            tool_num = input("Enter tool number: ").strip()
            try:
                idx = int(tool_num) - 1
                if 0 <= idx < len(tools):
                    tool_id, _ = tools[idx]
                    self.show_tool_info(tool_id)
                else:
                    print("\nInvalid tool number.")
            except ValueError:
                print("\nInvalid input.")
            self.show_category_tools(category)
        else:
            self.show_category_tools(category)

    def search_tools(self):
        """Search for tools"""
        keyword = input("\nEnter search keyword: ").strip()

        if not keyword:
            self.show_main_menu()
            return

        results = self.discovery.search_tools(keyword)

        print("\n" + "=" * 70)
        print(f"  Search Results for '{keyword}'")
        print("=" * 70 + "\n")

        if not results:
            print(f"  No tools found matching '{keyword}'\n")
        else:
            for tool_id, tool in results:
                status = "✓" if tool["available"] else "✗"
                print(f"  [{status}] {tool['name']} ({tool_id})")
                print(f"      Category: {tool['category']}")
                print(f"      {tool['description']}")
                print()

        input("\nPress Enter to continue...")
        self.show_main_menu()

    def list_all_tools(self):
        """List all available tools"""
        print("\n" + "=" * 70)
        print("  All Available Tools")
        print("=" * 70 + "\n")

        tools = sorted(self.discovery.get_all_tools().items(), key=lambda x: x[1]["category"])

        current_category = None
        for tool_id, tool in tools:
            if tool["category"] != current_category:
                current_category = tool["category"]
                print(f"\n  {current_category}:")
                print("  " + "-" * 40)

            status = "✓" if tool["available"] else "✗"
            print(f"    [{status}] {tool_id:12s} - {tool['name']}")

        print("\n  Legend: ✓ = Available, ✗ = Not Found")
        input("\nPress Enter to continue...")
        self.show_main_menu()

    def show_tool_info(self, tool_id: str):
        """Show detailed information about a tool"""
        tool = self.discovery.get_tool(tool_id)

        if not tool:
            print(f"\nTool '{tool_id}' not found.")
            return

        print("\n" + "=" * 70)
        print(f"  {tool['name']}")
        print("=" * 70)
        print(f"\nCommand ID: {tool_id}")
        print(f"Category:   {tool['category']}")
        print(f"Status:     {'Available ✓' if tool['available'] else 'Not Found ✗'}")
        print(f"\nDescription:")
        print(f"  {tool['description']}")

        if tool["keywords"]:
            print(f"\nKeywords: {', '.join(tool['keywords'])}")

        if tool["requires_api"]:
            print(f"\nAPI Keys Required:")
            for api_key in tool["requires_api"]:
                status = "✓" if os.getenv(api_key.split()[0]) else "✗"
                print(f"  [{status}] {api_key}")

        if tool["examples"]:
            print(f"\nUsage Examples:")
            for example in tool["examples"]:
                print(f"  $ {example}")

        print("\n" + "-" * 70)
        input("\nPress Enter to continue...")

    def show_api_status(self):
        """Show status of API keys"""
        print("\n" + "=" * 70)
        print("  API Key Status")
        print("=" * 70 + "\n")

        api_keys = {
            "VT_API_KEY": "VirusTotal API Key",
            "ABUSEIPDB_KEY": "AbuseIPDB API Key",
            "THREATFOX_API_KEY": "ThreatFox API Key (optional)",
            "URLHAUS_API_KEY": "URLHaus API Key (optional)",
        }

        for key, description in api_keys.items():
            status = "✓ Configured" if os.getenv(key) else "✗ Not configured"
            print(f"  [{status.split()[0]}] {description:30s} ({key})")

        print("\n  Configure API keys in .env file in the project root.")
        print("  Many tools will work without API keys but with limited functionality.")

        input("\nPress Enter to continue...")
        self.show_main_menu()

    def show_quick_start(self):
        """Show quick start guide"""
        print("\n" + "=" * 70)
        print("  Quick Start Guide")
        print("=" * 70)
        print(
            """
1. Basic Usage:

   Interactive Mode:
     $ vlair

   Direct Command:
     $ vlair <tool> [arguments]

   List All Tools:
     $ vlair list

   Get Tool Info:
     $ vlair info <tool>

2. Common Workflows:

   Analyze Suspicious Email:
     $ vlair eml suspicious.eml --vt --output report.json

   Extract IOCs from Threat Report:
     $ vlair ioc report.txt --format csv --output iocs.csv

   Check Hash Reputation:
     $ vlair hash <md5/sha1/sha256>

   Analyze Domain/IP:
     $ vlair intel malicious.com

   Scan for Malware:
     $ vlair yara scan /path/to/files --rules ./yaraScanner/rules/

3. Configuration:

   Create .env file with API keys:
     VT_API_KEY=your_virustotal_key
     ABUSEIPDB_KEY=your_abuseipdb_key

4. Get Help:

   General Help:
     $ vlair --help

   Tool-Specific Help:
     $ vlair <tool> --help

5. Advanced Features:

   - Batch processing with --file option
   - Multiple output formats (JSON, CSV, TXT)
   - Caching for improved performance
   - STIX 2.1 export support
        """
        )

        input("\nPress Enter to continue...")
        self.show_main_menu()


def print_usage():
    """Print usage information"""
    print(
        """
vlair - Security Operations Toolkit

Quick Start:
    vlair analyze <input>      Auto-detect and analyze (RECOMMENDED)
    vlair shell                Start the interactive shell (REPL)

The 'analyze' command automatically detects what you're analyzing and runs
the appropriate tools. Just give it a file, hash, IP, domain, or URL.
The 'shell' command opens a persistent prompt so you don't have to retype
'vlair' for every command.

Usage:
    vlair shell                Interactive shell (persistent session)
    vlair analyze <input>      Smart analysis (auto-detect input type)
    vlair workflow <name> <input>  Run pre-built investigation workflow
    vlair investigate <cmd>    Automated investigation commands
    vlair status               Show API key and tool status
    vlair                     Tool browser (interactive menu)
    vlair list                 List all available tools
    vlair info <tool>          Show detailed tool information
    vlair search <keyword>     Search for tools
    vlair <tool> [args]        Run a specific tool directly
    vlair --help               Show this help message
    vlair --version            Show version information

Examples - Smart Analyze:
    vlair analyze suspicious.eml           # Analyze email file
    vlair analyze 44d88612fea8a8f36...     # Check hash reputation
    vlair analyze malicious.com            # Get domain intelligence
    vlair analyze capture.pcap             # Analyze network traffic

Examples - Workflows:
    vlair workflow phishing-email suspicious.eml   # Full phishing investigation
    vlair workflow malware-triage sample.exe       # Malware analysis
    vlair workflow ioc-hunt indicators.txt         # Bulk IOC hunting
    vlair workflow network-forensics capture.pcap  # PCAP forensics
    vlair workflow log-investigation access.log    # Log analysis

Examples - Automated Investigation:
    vlair investigate phishing --file suspicious.eml --verbose
    vlair investigate phishing --file suspicious.eml --mock
    vlair investigate status INV-2026-01-31-ABCD1234
    vlair investigate list --last 24h
    vlair investigate results INV-2026-01-31-ABCD1234 --json

Output Options:
    --json      Machine-readable JSON output
    --verbose   Detailed progress and results
    --quiet     Just verdict + score (analyze only)
    --report [html|markdown|md]  Generate report file
    --output/-o <path>           Specify report output path

Individual Tools:
    eml          Email analysis and parsing
    ioc          IOC extraction from text
    hash         Hash reputation lookup
    intel        Domain/IP intelligence
    log          Log file analysis
    pcap         Network traffic analysis
    url          URL threat analysis
    yara         YARA malware scanning
    cert         SSL/TLS certificate analysis
    deobfuscate  Script deobfuscation
    threatfeed   Threat intelligence aggregation
    carve        File carving and extraction

Documentation: https://github.com/Vligai/secops-helper
    """
    )


def main():
    """Main entry point"""
    base_dir = Path(__file__).parent

    # Initialize discovery and management
    discovery = ToolDiscovery(base_dir)
    manager = ToolManager(discovery)
    menu = InteractiveMenu(discovery, manager)

    # Parse arguments
    if len(sys.argv) == 1:
        # No arguments - show interactive menu
        try:
            while True:
                menu.show_main_menu()
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            sys.exit(0)

    elif sys.argv[1] == "shell":
        from vlair.cli.shell import run_shell

        run_shell()
        sys.exit(0)

    elif sys.argv[1] in ["--help", "-h", "help"]:
        print_usage()
        sys.exit(0)

    elif sys.argv[1] in ["--version", "-v"]:
        print("vlair v4.0.0")
        print("Phase 5: Operationalization - Smart analyze command")
        sys.exit(0)

    elif sys.argv[1] == "list":
        # List all tools
        tools = sorted(discovery.get_all_tools().items(), key=lambda x: x[1]["category"])

        print("\nAvailable Tools:\n")
        current_category = None
        for tool_id, tool in tools:
            if tool["category"] != current_category:
                current_category = tool["category"]
                print(f"\n{current_category}:")
                print("-" * 40)

            status = "✓" if tool["available"] else "✗"
            print(f"  [{status}] {tool_id:12s} - {tool['name']}")

        print("\nUse 'vlair info <tool>' for detailed information")
        print("Use 'vlair <tool> --help' for usage help\n")

    elif sys.argv[1] == "info":
        if len(sys.argv) < 3:
            print("Usage: vlair info <tool>", file=sys.stderr)
            sys.exit(1)

        tool_id = sys.argv[2]
        tool = discovery.get_tool(tool_id)

        if not tool:
            print(f"Error: Unknown tool '{tool_id}'", file=sys.stderr)
            print("Run 'vlair list' to see available tools", file=sys.stderr)
            sys.exit(1)

        menu.show_tool_info(tool_id)

    elif sys.argv[1] == "search":
        if len(sys.argv) < 3:
            print("Usage: vlair search <keyword>", file=sys.stderr)
            sys.exit(1)

        keyword = sys.argv[2]
        results = discovery.search_tools(keyword)

        print(f"\nSearch Results for '{keyword}':\n")

        if not results:
            print(f"No tools found matching '{keyword}'\n")
        else:
            for tool_id, tool in results:
                status = "✓" if tool["available"] else "✗"
                print(f"  [{status}] {tool_id:12s} - {tool['name']}")
                print(f"      {tool['description']}\n")

    elif sys.argv[1] == "ai-stats":
        # AI usage statistics dashboard
        try:
            from vlair.ai.cache import AIResponseCache

            cache = AIResponseCache()
            stats = cache.get_stats()

            print("\nAI Usage Statistics")
            print("=" * 40)
            print(f"Today:      {stats['today_requests']} requests, {stats['today_tokens']:,} tokens, ~${stats['cost_estimate_today']:.4f}")
            print(f"This month: {stats['month_requests']} requests, {stats['month_tokens']:,} tokens, ~${stats['cost_estimate_month']:.4f}")
            print(f"Cache hit rate: {stats['cache_hit_rate']}%")

            breakdown = stats.get("provider_breakdown", {})
            if breakdown:
                print("\nProvider breakdown (today, non-cached):")
                for pname, pdata in breakdown.items():
                    print(f"  {pname}: {pdata['requests']} requests, {pdata['tokens']:,} tokens")
            else:
                provider = os.getenv("VLAIR_AI_PROVIDER", "anthropic")
                print(f"\nProvider: {provider}")

            print()
        except Exception as _stats_err:
            print(f"Error fetching AI stats: {_stats_err}", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == "ai":
        # AI subcommand dispatcher
        if len(sys.argv) < 3 or sys.argv[2] in ("--help", "-h", "help"):
            print("Usage: vlair ai <subcommand> [options]", file=sys.stderr)
            print("\nSubcommands:", file=sys.stderr)
            print("  playbook <type>   Generate an incident response playbook", file=sys.stderr)
            print("\nPlaybook types:", file=sys.stderr)
            print("  phishing, ransomware, c2, data_exfil, generic", file=sys.stderr)
            print("\nOptions:", file=sys.stderr)
            print("  --context <str>          Context string for the incident", file=sys.stderr)
            print("  --depth quick|standard|thorough", file=sys.stderr)
            print("  --json                   Machine-readable JSON output", file=sys.stderr)
            print("  --output/-o <path>       Save to file", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  vlair ai playbook phishing", file=sys.stderr)
            print("  vlair ai playbook ransomware --depth thorough", file=sys.stderr)
            print("  vlair ai playbook c2 --json --output playbook.json", file=sys.stderr)
            sys.exit(0)

        ai_subcmd = sys.argv[2]

        if ai_subcmd == "playbook":
            if len(sys.argv) < 4:
                print("Usage: vlair ai playbook <incident-type> [options]", file=sys.stderr)
                print("Types: phishing, ransomware, c2, data_exfil", file=sys.stderr)
                sys.exit(1)

            incident_type = sys.argv[3]
            args_list = sys.argv[4:]
            json_output = "--json" in args_list or "-j" in args_list
            output_path = None
            context_str = None
            ai_depth = "standard"

            for i, arg in enumerate(args_list):
                if arg in ("--output", "-o") and i + 1 < len(args_list):
                    output_path = args_list[i + 1]
                if arg == "--context" and i + 1 < len(args_list):
                    context_str = args_list[i + 1]
                if arg == "--depth" and i + 1 < len(args_list):
                    if args_list[i + 1] in ("quick", "standard", "thorough"):
                        ai_depth = args_list[i + 1]

            context = {}
            if context_str:
                context["description"] = context_str

            try:
                from vlair.ai import PlaybookGenerator

                gen = PlaybookGenerator()
                playbook = gen.generate(incident_type, context=context, depth=ai_depth)

                if json_output:
                    playbook_str = json.dumps(playbook, indent=2, default=str)
                    if output_path:
                        Path(output_path).write_text(playbook_str, encoding="utf-8")
                        print(f"Playbook saved to: {output_path}")
                    else:
                        print(playbook_str)
                else:
                    # Human-readable output
                    print(f"\n{'='*66}")
                    print(f"  {playbook.get('title', 'Incident Response Playbook')}")
                    print(f"{'='*66}")
                    print(f"Severity: {playbook.get('severity', 'HIGH')}")
                    print()

                    for step in playbook.get("steps", []):
                        print(f"Step {step.get('step', '?')}: {step.get('title', '')}  [{step.get('time', '')}]")
                        for action in step.get("actions", []):
                            print(f"  - {action}")
                        print()

                    siem = playbook.get("siem_queries", {})
                    if siem:
                        print("SIEM Queries:")
                        for platform, query in siem.items():
                            print(f"  [{platform}] {query}")
                        print()

                    contain = playbook.get("containment_actions", [])
                    if contain:
                        print("Containment:")
                        for action in contain:
                            print(f"  - {action}")
                        print()

                    if output_path:
                        # Save markdown version
                        lines = [f"# {playbook.get('title', 'Playbook')}\n"]
                        for step in playbook.get("steps", []):
                            lines.append(f"## Step {step.get('step')}: {step.get('title')} ({step.get('time', '')})\n")
                            for action in step.get("actions", []):
                                lines.append(f"- {action}")
                            lines.append("")
                        Path(output_path).write_text("\n".join(lines), encoding="utf-8")
                        print(f"Playbook saved to: {output_path}")

            except Exception as _pb_err:
                print(f"Error generating playbook: {_pb_err}", file=sys.stderr)
                import traceback; traceback.print_exc()
                sys.exit(1)

        else:
            print(f"Unknown ai subcommand: {ai_subcmd}", file=sys.stderr)
            print("Use 'vlair ai --help' for help", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == "analyze":
        # Smart analyze command - auto-detect and run appropriate tools
        if len(sys.argv) < 3:
            print(
                "Usage: vlair analyze <input> [--verbose] [--json] [--quiet] [--ai [--depth quick|standard|thorough]] [--dry-run] [--report ai-markdown]",
                file=sys.stderr,
            )
            print("\nExamples:", file=sys.stderr)
            print("  vlair analyze suspicious.eml                   # Auto-detect email", file=sys.stderr)
            print("  vlair analyze 44d88612...                      # Auto-detect hash", file=sys.stderr)
            print("  vlair analyze malicious.com                    # Auto-detect domain", file=sys.stderr)
            print("  vlair analyze 192.168.1.1                      # Auto-detect IP", file=sys.stderr)
            print("  vlair analyze suspicious.eml --ai              # Add AI assessment", file=sys.stderr)
            print("  vlair analyze hash123 --ai --depth thorough    # Deep AI analysis", file=sys.stderr)
            print("  vlair analyze hash123 --ai --dry-run           # Preview AI data", file=sys.stderr)
            print("  vlair analyze hash123 --ai --report ai-markdown # AI Markdown report", file=sys.stderr)
            sys.exit(1)

        try:
            import time as _time

            _analyze_start = _time.time()

            from vlair.core.analyzer import Analyzer
            from vlair.core.reporter import Reporter

            # Parse analyze arguments
            input_value = sys.argv[2]
            verbose = "--verbose" in sys.argv or "-v" in sys.argv[3:]
            json_output = "--json" in sys.argv or "-j" in sys.argv
            quiet = "--quiet" in sys.argv or "-q" in sys.argv
            ai_enabled = "--ai" in sys.argv
            dry_run = "--dry-run" in sys.argv

            # Parse report and AI arguments
            report_format = None
            output_path = None
            ai_depth = "standard"
            args_list = sys.argv[3:]
            for i, arg in enumerate(args_list):
                if arg == "--report":
                    if i + 1 < len(args_list) and args_list[i + 1] in ("html", "markdown", "md", "ai-markdown"):
                        report_format = args_list[i + 1]
                    else:
                        report_format = "html"
                if arg in ("--output", "-o"):
                    if i + 1 < len(args_list):
                        output_path = args_list[i + 1]
                if arg == "--depth" and i + 1 < len(args_list):
                    if args_list[i + 1] in ("quick", "standard", "thorough"):
                        ai_depth = args_list[i + 1]

            # If --dry-run without --ai, enable --ai implicitly
            if dry_run and not ai_enabled:
                ai_enabled = True

            # Run analysis
            analyzer = Analyzer(verbose=verbose)
            result = analyzer.analyze(input_value)

            # Run AI analysis if requested
            ai_result = None
            if ai_enabled:
                _AI_TYPE_MAP = {
                    "hash_md5": "hash",
                    "hash_sha1": "hash",
                    "hash_sha256": "hash",
                    "ip": "ip",
                    "domain": "domain",
                    "url": "url",
                    "email": "email",
                    "log": "log",
                    "pcap": "pcap",
                    "script": "script",
                    "ioc_list": "ioc",
                    "file": "hash",
                }
                try:
                    from vlair.ai import ThreatSummarizer

                    _summarizer = ThreatSummarizer()

                    if dry_run:
                        # Show what would be sent without calling AI
                        _ioc_type = _AI_TYPE_MAP.get(str(result["type"]), "unknown")
                        ai_result = _summarizer.summarize(
                            input_value, _ioc_type, result["tool_results"], ai_depth, dry_run=True
                        )
                        print(ai_result["threat_context"])
                        sys.exit(0)
                    elif _summarizer.is_available():
                        if not quiet:
                            print("[*] Running AI analysis...", file=sys.stderr)
                        _ioc_type = _AI_TYPE_MAP.get(str(result["type"]), "unknown")
                        ai_result = _summarizer.summarize(
                            input_value, _ioc_type, result["tool_results"], ai_depth
                        )
                    else:
                        if not quiet:
                            print(
                                "[!] AI unavailable: set ANTHROPIC_API_KEY (or OPENAI_API_KEY / configure Ollama) to enable",
                                file=sys.stderr,
                            )
                except ImportError:
                    if not quiet:
                        print("[!] AI module unavailable (pip install -e '.[ai]')", file=sys.stderr)
                except Exception as _ai_err:
                    if not quiet:
                        print(f"[!] AI analysis failed: {_ai_err}", file=sys.stderr)

            # Format output
            reporter = Reporter()

            if quiet:
                print(reporter.format_quiet(result["scorer"]))
            elif json_output:
                import json as _json

                _json_data = _json.loads(
                    reporter.format_json(
                        result["input"],
                        result["type"],
                        result["scorer"],
                        result["iocs"],
                        result["tool_results"],
                    )
                )
                if ai_result is not None:
                    _json_data["ai_analysis"] = ai_result
                print(_json.dumps(_json_data, indent=2, default=str))
            elif verbose:
                print(
                    reporter.format_verbose(
                        result["input"],
                        result["type"],
                        result["scorer"],
                        result["iocs"],
                        result["tool_results"],
                    )
                )
                if ai_result is not None:
                    print(_format_ai_assessment(ai_result))
            else:
                print(
                    reporter.format_console(
                        result["input"],
                        result["type"],
                        result["scorer"],
                        result["iocs"],
                        result["tool_results"],
                    )
                )
                if ai_result is not None:
                    print(_format_ai_assessment(ai_result))

            # Generate report if requested
            if report_format == "ai-markdown" and ai_result is not None:
                try:
                    from vlair.ai import AIReporter

                    ai_reporter = AIReporter()
                    _ioc_type_for_report = _AI_TYPE_MAP.get(str(result.get("type", "")), "unknown") if "_AI_TYPE_MAP" in dir() else "unknown"
                    md_content = ai_reporter.to_markdown(
                        ioc_value=input_value,
                        ioc_type=_ioc_type_for_report,
                        tool_result=result.get("tool_results", {}),
                        ai_result=ai_result,
                    )
                    report_path = ai_reporter.save(md_content, "markdown", output_path)
                    print(f"\nAI Markdown report saved to: {report_path}", file=sys.stderr)
                except Exception as _rpt_err:
                    print(f"[!] Failed to generate AI Markdown report: {_rpt_err}", file=sys.stderr)
            elif report_format and report_format != "ai-markdown":
                from vlair.core.report_generator import ReportGenerator

                generator = ReportGenerator()
                report_path = generator.generate(result, report_format, output_path)
                print(f"\nReport saved to: {report_path}", file=sys.stderr)

            # Record in history
            try:
                from vlair.core.history import AnalysisHistory

                history = AnalysisHistory()
                scorer = result["scorer"]
                history.record(
                    input_value=input_value,
                    input_type=result["type"],
                    verdict=scorer.get_summary().get("verdict", "UNKNOWN"),
                    risk_score=scorer.get_summary().get("risk_score"),
                    command="analyze",
                    duration_seconds=_time.time() - _analyze_start,
                )
            except Exception:
                pass

            sys.exit(reporter.get_exit_code(result["scorer"]))

        except ImportError as e:
            print(f"Error: Could not load analyzer module: {e}", file=sys.stderr)
            print("Make sure core/ directory exists with analyzer.py", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during analysis: {e}", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == "check":
        # Quick indicator lookup - direct tool invocation without full analysis pipeline
        if len(sys.argv) < 3:
            print("Usage: vlair check <type> <value> [--json] [--verbose]", file=sys.stderr)
            print("       vlair check <file>          # Auto-detect IOC file", file=sys.stderr)
            print("\nTypes:", file=sys.stderr)
            print("  hash    <hash>     Look up a file hash (MD5/SHA1/SHA256)", file=sys.stderr)
            print("  domain  <domain>   Get domain intelligence", file=sys.stderr)
            print("  ip      <ip>       Get IP intelligence", file=sys.stderr)
            print("  url     <url>      Check URL reputation", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  vlair check hash 44d88612fea8a8f36de82e1278abb02f", file=sys.stderr)
            print("  vlair check domain malicious.com", file=sys.stderr)
            print("  vlair check ip 1.2.3.4 --json", file=sys.stderr)
            print("  vlair check url http://bad.com/payload", file=sys.stderr)
            print("  vlair check iocs.txt", file=sys.stderr)
            sys.exit(1)

        check_type = sys.argv[2]
        verbose = "--verbose" in sys.argv or "-v" in sys.argv[3:]
        json_output = "--json" in sys.argv or "-j" in sys.argv

        try:
            import time as _time

            start_time = _time.time()

            # Known type keywords route directly to tools
            if check_type == "hash":
                if len(sys.argv) < 4:
                    print("Error: Missing hash value", file=sys.stderr)
                    print("Usage: vlair check hash <md5|sha1|sha256>", file=sys.stderr)
                    sys.exit(1)
                hash_value = sys.argv[3]
                from vlair.tools.hash_lookup import HashLookup

                lookup = HashLookup(verbose=verbose)
                result = lookup.lookup(hash_value)
                indicator_type = "hash"

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get("verdict", "UNKNOWN")
                    detections = result.get("detections", 0)
                    total = result.get("total_engines", 0)
                    print(f"Hash: {hash_value}")
                    print(f"Verdict: {verdict}")
                    if detections or total:
                        print(f"Detections: {detections}/{total}")
                    malware_family = result.get("malware_family") or result.get(
                        "suggested_threat_label"
                    )
                    if malware_family:
                        print(f"Family: {malware_family}")
                    sources = result.get("sources", [])
                    if sources:
                        print(f"Sources: {', '.join(sources)}")

            elif check_type == "domain":
                if len(sys.argv) < 4:
                    print("Error: Missing domain value", file=sys.stderr)
                    print("Usage: vlair check domain <domain>", file=sys.stderr)
                    sys.exit(1)
                domain_value = sys.argv[3]
                from vlair.tools.domain_ip_intel import (
                    DomainIPIntelligence as DomainIPIntel,
                )

                intel = DomainIPIntel(verbose=verbose)
                result = intel.lookup(domain_value)
                indicator_type = "domain"

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get("verdict", "UNKNOWN")
                    risk_score = result.get("risk_score", 0)
                    print(f"Domain: {domain_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    dns = result.get("dns", {})
                    if dns.get("a_records"):
                        print(f"IPs: {', '.join(dns['a_records'][:5])}")
                    categories = result.get("categories", [])
                    if categories:
                        print(f"Categories: {', '.join(categories[:5])}")

            elif check_type == "ip":
                if len(sys.argv) < 4:
                    print("Error: Missing IP address", file=sys.stderr)
                    print("Usage: vlair check ip <ip_address>", file=sys.stderr)
                    sys.exit(1)
                ip_value = sys.argv[3]
                from vlair.tools.domain_ip_intel import (
                    DomainIPIntelligence as DomainIPIntel,
                )

                intel = DomainIPIntel(verbose=verbose)
                result = intel.lookup(ip_value)
                indicator_type = "ip"

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get("verdict", "UNKNOWN")
                    risk_score = result.get("risk_score", 0)
                    print(f"IP: {ip_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    abuse_score = result.get("abuse_confidence_score")
                    if abuse_score is not None:
                        print(f"Abuse Score: {abuse_score}%")
                    country = result.get("country")
                    if country:
                        print(f"Country: {country}")

            elif check_type == "url":
                if len(sys.argv) < 4:
                    print("Error: Missing URL", file=sys.stderr)
                    print("Usage: vlair check url <url>", file=sys.stderr)
                    sys.exit(1)
                url_value = sys.argv[3]
                from vlair.tools.url_analyzer import URLAnalyzer

                analyzer = URLAnalyzer(verbose=verbose)
                result = analyzer.analyze(url_value)
                indicator_type = "url"

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get("verdict", "UNKNOWN")
                    risk_score = result.get("risk_score", 0)
                    print(f"URL: {url_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    threats = result.get("threats", [])
                    if threats:
                        for threat in threats[:5]:
                            print(f"  [!] {threat}")

            elif os.path.isfile(check_type):
                # Auto-detect file as IOC list
                from vlair.core.analyzer import Analyzer
                from vlair.core.reporter import Reporter

                analyzer_instance = Analyzer(verbose=verbose)
                result = analyzer_instance.analyze(check_type)
                indicator_type = result.get("type", "file")

                reporter = Reporter()
                if json_output:
                    print(
                        reporter.format_json(
                            result["input"],
                            result["type"],
                            result["scorer"],
                            result["iocs"],
                            result["tool_results"],
                        )
                    )
                else:
                    print(
                        reporter.format_console(
                            result["input"],
                            result["type"],
                            result["scorer"],
                            result["iocs"],
                            result["tool_results"],
                        )
                    )
                sys.exit(reporter.get_exit_code(result["scorer"]))

            else:
                print(f"Error: Unknown check type '{check_type}'", file=sys.stderr)
                print("Valid types: hash, domain, ip, url", file=sys.stderr)
                print("Or provide a file path for batch IOC checking", file=sys.stderr)
                sys.exit(1)

            # Record in history
            duration = _time.time() - start_time
            try:
                from vlair.core.history import AnalysisHistory

                history = AnalysisHistory()
                verdict_val = (
                    result.get("verdict", "UNKNOWN") if isinstance(result, dict) else "UNKNOWN"
                )
                score_val = result.get("risk_score") if isinstance(result, dict) else None
                history.record(
                    input_value=sys.argv[3] if len(sys.argv) > 3 else check_type,
                    input_type=indicator_type,
                    verdict=verdict_val,
                    risk_score=score_val,
                    command="check",
                    duration_seconds=duration,
                )
            except Exception:
                pass

        except ImportError as e:
            print(f"Error: Could not load tool module: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during check: {e}", file=sys.stderr)
            if verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    elif sys.argv[1] == "workflow":
        # Pre-built investigation workflows
        if len(sys.argv) < 3:
            print("Usage: vlair workflow <name> <input> [--verbose] [--json]", file=sys.stderr)
            print("\nAvailable workflows:", file=sys.stderr)
            print(
                "  phishing-email     Comprehensive phishing email investigation", file=sys.stderr
            )
            print("  malware-triage     Quick malware analysis and triage", file=sys.stderr)
            print("  ioc-hunt           Bulk IOC threat hunting", file=sys.stderr)
            print("  network-forensics  Network traffic forensic analysis", file=sys.stderr)
            print("  log-investigation  Security log investigation", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  vlair workflow phishing-email suspicious.eml", file=sys.stderr)
            print("  vlair workflow malware-triage sample.exe --verbose", file=sys.stderr)
            print("  vlair workflow ioc-hunt iocs.txt --json", file=sys.stderr)
            sys.exit(1)

        workflow_name = sys.argv[2]

        if len(sys.argv) < 4:
            print(f"Error: Missing input for workflow '{workflow_name}'", file=sys.stderr)
            print(f"Usage: vlair workflow {workflow_name} <input>", file=sys.stderr)
            sys.exit(1)

        input_value = sys.argv[3]
        verbose = "--verbose" in sys.argv or "-v" in sys.argv[4:]
        json_output = "--json" in sys.argv or "-j" in sys.argv

        # Parse report arguments
        report_format = None
        output_path = None
        args_list = sys.argv[4:]
        for i, arg in enumerate(args_list):
            if arg == "--report":
                if i + 1 < len(args_list) and args_list[i + 1] in ("html", "markdown", "md"):
                    report_format = args_list[i + 1]
                else:
                    report_format = "html"
            if arg in ("--output", "-o"):
                if i + 1 < len(args_list):
                    output_path = args_list[i + 1]

        try:
            from vlair.core.workflow import WorkflowRegistry
            from vlair.core.reporter import Reporter

            # Import workflows to register them
            from workflows import (
                PhishingEmailWorkflow,
                MalwareTriageWorkflow,
                IOCHuntWorkflow,
                NetworkForensicsWorkflow,
                LogInvestigationWorkflow,
            )

            # Get workflow class
            workflow_class = WorkflowRegistry.get(workflow_name)
            if not workflow_class:
                print(f"Error: Unknown workflow '{workflow_name}'", file=sys.stderr)
                print("Run 'vlair workflow' to see available workflows", file=sys.stderr)
                sys.exit(1)

            # Execute workflow
            workflow_instance = workflow_class(verbose=verbose)
            result = workflow_instance.execute(input_value)

            # Generate report before potentially modifying result for JSON output
            if report_format:
                from vlair.core.report_generator import ReportGenerator

                generator = ReportGenerator()
                report_path = generator.generate(result, report_format, output_path)
                print(f"\nReport saved to: {report_path}", file=sys.stderr)

            # Format output
            reporter = Reporter()

            if json_output:
                # Convert scorer to summary for JSON
                result["summary"] = result["scorer"].get_summary()
                result["findings"] = result["scorer"].get_findings()
                result["recommendations"] = result["scorer"].get_recommendations()
                del result["scorer"]
                print(json.dumps(result, indent=2, default=str))
            else:
                # Console output
                print(
                    reporter.format_console(
                        result["input"],
                        result["type"],
                        result["scorer"],
                        result["iocs"],
                        result["tool_results"],
                    )
                )

                # Print workflow-specific info
                print(f"\nWorkflow: {result['workflow']}")
                print(f"Steps completed: {result['steps_completed']}/{result['steps_total']}")
                print(f"Duration: {result['duration_seconds']:.1f}s")

            sys.exit(reporter.get_exit_code(result["scorer"]) if "scorer" in result else 0)

        except ImportError as e:
            print(f"Error: Could not load workflow module: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during workflow execution: {e}", file=sys.stderr)
            if verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    elif sys.argv[1] == "investigate":
        # Investigation automation commands
        if len(sys.argv) < 3:
            print("Usage: vlair investigate <command> [args]", file=sys.stderr)
            print("\nCommands:", file=sys.stderr)
            print(
                "  phishing --file <eml>    Run phishing investigation on email file",
                file=sys.stderr,
            )
            print("  status <id>              Check investigation status", file=sys.stderr)
            print("  list [--last 24h]        List recent investigations", file=sys.stderr)
            print("  results <id>             Get investigation results", file=sys.stderr)
            print(
                "  interactive              Start interactive investigation mode", file=sys.stderr
            )
            print("\nExamples:", file=sys.stderr)
            print("  vlair investigate phishing --file suspicious.eml --verbose", file=sys.stderr)
            print("  vlair investigate phishing --file suspicious.eml --mock", file=sys.stderr)
            print("  vlair investigate status INV-2026-01-31-ABCD1234", file=sys.stderr)
            print("  vlair investigate list --last 24h", file=sys.stderr)
            print("  vlair investigate results INV-2026-01-31-ABCD1234 --json", file=sys.stderr)
            sys.exit(1)

        investigate_cmd = sys.argv[2]

        if investigate_cmd == "interactive":
            # Legacy interactive investigation mode
            try:
                from vlair.core.interactive import InteractiveInvestigation

                investigation = InteractiveInvestigation()
                investigation.run()
                sys.exit(0)

            except ImportError as e:
                print(f"Error: Could not load interactive module: {e}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error during investigation: {e}", file=sys.stderr)
                sys.exit(1)

        elif investigate_cmd == "phishing":
            # Automated phishing investigation
            verbose = "--verbose" in sys.argv or "-v" in sys.argv[3:]
            json_output = "--json" in sys.argv or "-j" in sys.argv
            use_mock = "--mock" in sys.argv

            # Parse --file argument
            file_path = None
            args_list = sys.argv[3:]
            for i, arg in enumerate(args_list):
                if arg == "--file" and i + 1 < len(args_list):
                    file_path = args_list[i + 1]
                    break

            if not file_path:
                print("Error: --file <eml_path> is required", file=sys.stderr)
                print(
                    "Usage: vlair investigate phishing --file <eml_path> [--verbose] [--mock] [--json]",
                    file=sys.stderr,
                )
                sys.exit(1)

            if not os.path.exists(file_path):
                print(f"Error: File not found: {file_path}", file=sys.stderr)
                sys.exit(1)

            try:
                from vlair.investigate import InvestigationEngine, PlaybookRegistry
                from vlair.investigate.playbooks.phishing import PhishingPlaybook

                # Ensure playbook is registered
                PlaybookRegistry.register(PhishingPlaybook)

                # Set up connectors
                connectors = {}
                if use_mock:
                    from vlair.investigate.connectors.mock import (
                        MockEmailConnector,
                        MockSIEMConnector,
                    )

                    connectors["email"] = MockEmailConnector(scenario="phishing")
                    connectors["siem"] = MockSIEMConnector(scenario="phishing")

                # Create and run investigation
                engine = InvestigationEngine(connectors=connectors, verbose=verbose)
                state = engine.start_investigation(
                    playbook_name="phishing",
                    inputs={"file_path": file_path},
                    auto_run=True,
                )

                # Output results
                if json_output:
                    print(json.dumps(state.to_dict(), indent=2, default=str))
                else:
                    print(f"\n{'='*60}")
                    print(f"  Investigation Complete: {state.id}")
                    print(f"{'='*60}")
                    print(f"\nStatus:     {state.status.value.upper()}")
                    print(f"Risk Score: {state.risk_score}/100")
                    print(f"Verdict:    {state.verdict}")

                    # Show steps summary
                    completed = len([s for s in state.steps if s.status.value == "completed"])
                    total = len(state.steps)
                    print(f"Steps:      {completed}/{total} completed")

                    # Show findings
                    if state.findings:
                        print(f"\nFindings ({len(state.findings)}):")
                        for finding in state.findings[:10]:
                            severity = finding.get("severity", "?").upper()
                            message = finding.get("message", "")
                            print(f"  [{severity:8s}] {message}")

                    # Show IOCs
                    total_iocs = sum(len(v) for v in state.iocs.values())
                    if total_iocs > 0:
                        print(f"\nIOCs Extracted ({total_iocs}):")
                        for ioc_type, values in state.iocs.items():
                            if values:
                                print(f"  {ioc_type}: {len(values)}")

                    # Show remediation actions
                    if state.remediation_actions:
                        print(f"\nRemediation Actions ({len(state.remediation_actions)}):")
                        for action in state.remediation_actions:
                            print(f"  - {action.name}")

                    print(f"\nInvestigation ID: {state.id}")
                    print("Use 'vlair investigate results <id> --json' for full details")

                # Exit with code based on verdict
                if state.verdict == "MALICIOUS":
                    sys.exit(2)
                elif state.verdict == "SUSPICIOUS":
                    sys.exit(1)
                else:
                    sys.exit(0)

            except ImportError as e:
                print(f"Error: Could not load investigation module: {e}", file=sys.stderr)
                import traceback

                traceback.print_exc()
                sys.exit(1)
            except Exception as e:
                print(f"Error during investigation: {e}", file=sys.stderr)
                if verbose:
                    import traceback

                    traceback.print_exc()
                sys.exit(1)

        elif investigate_cmd == "status":
            # Check investigation status
            if len(sys.argv) < 4:
                print("Usage: vlair investigate status <investigation-id>", file=sys.stderr)
                sys.exit(1)

            investigation_id = sys.argv[3]

            try:
                from vlair.investigate import InvestigationEngine

                engine = InvestigationEngine()
                state = engine.get_investigation(investigation_id)

                if not state:
                    print(f"Investigation not found: {investigation_id}", file=sys.stderr)
                    sys.exit(1)

                print(f"\nInvestigation: {state.id}")
                print(f"Type:          {state.type}")
                print(f"Status:        {state.status.value.upper()}")
                print(f"Risk Score:    {state.risk_score}/100")
                print(f"Verdict:       {state.verdict}")
                print(f"Created:       {state.created_at}")
                if state.completed_at:
                    print(f"Completed:     {state.completed_at}")
                if state.error:
                    print(f"Error:         {state.error}")

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif investigate_cmd == "list":
            # List investigations
            limit = 20
            since_hours = None

            # Parse arguments
            args_list = sys.argv[3:]
            for i, arg in enumerate(args_list):
                if arg == "--last" and i + 1 < len(args_list):
                    time_str = args_list[i + 1]
                    if time_str.endswith("h"):
                        since_hours = int(time_str[:-1])
                    elif time_str.endswith("d"):
                        since_hours = int(time_str[:-1]) * 24
                if arg == "--limit" and i + 1 < len(args_list):
                    limit = int(args_list[i + 1])

            try:
                from vlair.investigate import InvestigationEngine

                engine = InvestigationEngine()
                investigations = engine.list_investigations(limit=limit, since_hours=since_hours)

                if not investigations:
                    print("No investigations found")
                    sys.exit(0)

                print(f"\nRecent Investigations ({len(investigations)}):")
                print("-" * 80)
                print(f"{'ID':<30} {'Type':<12} {'Status':<12} {'Verdict':<12} {'Score':<6}")
                print("-" * 80)

                for inv in investigations:
                    inv_id = inv.get("id", "?")[:28]
                    inv_type = inv.get("type", "?")[:10]
                    status = inv.get("status", "?")[:10]
                    verdict = inv.get("verdict", "?")[:10]
                    score = str(inv.get("risk_score", "?"))
                    print(f"{inv_id:<30} {inv_type:<12} {status:<12} {verdict:<12} {score:<6}")

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif investigate_cmd == "results":
            # Get investigation results
            if len(sys.argv) < 4:
                print(
                    "Usage: vlair investigate results <investigation-id> [--json]", file=sys.stderr
                )
                sys.exit(1)

            investigation_id = sys.argv[3]
            json_output = "--json" in sys.argv

            try:
                from vlair.investigate import InvestigationEngine

                engine = InvestigationEngine()
                state = engine.get_investigation(investigation_id)

                if not state:
                    print(f"Investigation not found: {investigation_id}", file=sys.stderr)
                    sys.exit(1)

                if json_output:
                    print(json.dumps(state.to_dict(), indent=2, default=str))
                else:
                    print(f"\n{'='*70}")
                    print(f"  Investigation Results: {state.id}")
                    print(f"{'='*70}")

                    print(f"\nOverview:")
                    print(f"  Type:       {state.type}")
                    print(f"  Status:     {state.status.value.upper()}")
                    print(f"  Risk Score: {state.risk_score}/100")
                    print(f"  Verdict:    {state.verdict}")

                    if state.get_duration_seconds():
                        print(f"  Duration:   {state.get_duration_seconds():.1f}s")

                    print(f"\nSteps ({len(state.steps)}):")
                    for step in state.steps:
                        status_icon = (
                            "[+]"
                            if step.status.value == "completed"
                            else "[-]" if step.status.value == "failed" else "[.]"
                        )
                        duration = (
                            f"({step.duration_seconds:.1f}s)" if step.duration_seconds else ""
                        )
                        print(f"  {status_icon} {step.name} {duration}")
                        if step.error:
                            print(f"      Error: {step.error}")

                    if state.findings:
                        print(f"\nFindings ({len(state.findings)}):")
                        for finding in state.findings:
                            severity = finding.get("severity", "?").upper()
                            message = finding.get("message", "")
                            print(f"  [{severity:8s}] {message}")

                    total_iocs = sum(len(v) for v in state.iocs.values())
                    if total_iocs > 0:
                        print(f"\nIOCs ({total_iocs}):")
                        for ioc_type, values in state.iocs.items():
                            if values:
                                print(f"  {ioc_type}:")
                                for v in values[:5]:
                                    print(f"    - {v}")
                                if len(values) > 5:
                                    print(f"    ... and {len(values) - 5} more")

                    if state.remediation_actions:
                        print(f"\nRemediation Actions ({len(state.remediation_actions)}):")
                        for action in state.remediation_actions:
                            status = action.status.value.upper()
                            print(f"  [{status:8s}] {action.name}")
                            print(f"             Target: {action.target}")

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        else:
            print(f"Unknown investigate command: {investigate_cmd}", file=sys.stderr)
            print("Use 'vlair investigate' for help", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == "status":
        # Quick status dashboard
        print("\nvlair Status Dashboard")
        print("=" * 50)

        # Check API keys
        from dotenv import load_dotenv

        load_dotenv()

        api_keys = {
            "VT_API_KEY": "VirusTotal",
            "ABUSEIPDB_KEY": "AbuseIPDB",
            "THREATFOX_API_KEY": "ThreatFox",
            "URLHAUS_API_KEY": "URLhaus",
        }

        print("\nAPI Keys:")
        configured_count = 0
        for key, name in api_keys.items():
            if os.getenv(key):
                print(f"  [+] {name:15s}: Configured")
                configured_count += 1
            else:
                print(f"  [-] {name:15s}: Not set")
        print(f"      ({configured_count}/{len(api_keys)} configured)")

        # Check tool availability
        base_path = Path(__file__).parent
        tool_files = {
            "EML Parser": base_path / "emlAnalysis" / "emlParser.py",
            "IOC Extractor": base_path / "iocExtractor" / "extractor.py",
            "Hash Lookup": base_path / "hashLookup" / "lookup.py",
            "Domain/IP Intel": base_path / "domainIpIntel" / "intel.py",
            "Log Analyzer": base_path / "logAnalysis" / "analyzer.py",
            "PCAP Analyzer": base_path / "pcapAnalyzer" / "analyzer.py",
            "URL Analyzer": base_path / "urlAnalyzer" / "analyzer.py",
            "YARA Scanner": base_path / "yaraScanner" / "scanner.py",
            "Cert Analyzer": base_path / "certAnalyzer" / "analyzer.py",
            "Deobfuscator": base_path / "deobfuscator" / "deobfuscator.py",
            "Threat Feeds": base_path / "threatFeedAggregator" / "aggregator.py",
            "File Carver": base_path / "fileCarver" / "carver.py",
        }

        available_count = sum(1 for p in tool_files.values() if p.exists())
        print(f"\nTools: {available_count}/{len(tool_files)} available")

        # Cache statistics
        print("\nCache:")
        try:
            from common.cache_manager import get_cache

            cache = get_cache()
            print(f"  Backend: {cache.backend}")
            print(
                f"  Session stats - Hits: {cache.stats['hits']}, "
                f"Misses: {cache.stats['misses']}, "
                f"Sets: {cache.stats['sets']}"
            )
        except Exception:
            print("  Not available")

        # Threat feed freshness
        print("\nThreat Feeds:")
        try:
            feeds_db = Path.home() / ".threatFeedAggregator" / "feeds.db"
            if feeds_db.exists():
                import sqlite3

                conn = sqlite3.connect(str(feeds_db))
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM iocs")
                ioc_count = cursor.fetchone()[0]
                cursor.execute("SELECT MAX(last_seen) FROM iocs")
                last_update = cursor.fetchone()[0]
                conn.close()
                print(f"  IOCs in database: {ioc_count}")
                print(f"  Last updated: {last_update or 'Never'}")
            else:
                print("  Database not initialized (run: vlair feeds update)")
        except Exception:
            print("  Not available")

        # Recent analysis history
        print("\nRecent Analyses:")
        try:
            from vlair.core.history import AnalysisHistory

            history = AnalysisHistory()
            stats = history.get_stats()

            if stats["total_analyses"] > 0:
                print(f"  Total: {stats['total_analyses']}")
                if stats["verdicts"]:
                    verdict_str = ", ".join(f"{v}: {c}" for v, c in stats["verdicts"].items())
                    print(f"  Verdicts: {verdict_str}")
                if stats["last_analysis"]:
                    print(f"  Last: {stats['last_analysis']}")

                # Show last 5 analyses
                recent = history.get_recent(5)
                if recent:
                    print("\n  Last 5:")
                    for entry in recent:
                        verdict = entry.get("verdict", "?")
                        score = entry.get("risk_score")
                        score_str = f" ({score}/100)" if score is not None else ""
                        ts = entry["timestamp"][:16].replace("T", " ")
                        inp = entry["input_value"]
                        if len(inp) > 30:
                            inp = inp[:27] + "..."
                        print(f"    {ts}  {inp:30s}  {verdict}{score_str}")
            else:
                print("  No analyses recorded yet")
        except Exception:
            print("  History not available")

        # Features summary
        print("\nFeatures:")
        print("  [+] Smart analyze command (vlair analyze)")
        print("  [+] Quick check command (vlair check)")
        print("  [+] Pre-built workflows (5)")
        print("  [+] Interactive investigation mode")
        print("  [+] Report generation (HTML/Markdown)")
        print()

    else:
        # Run a tool
        tool_id = sys.argv[1]
        tool_args = sys.argv[2:]

        manager.run_tool(tool_id, tool_args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except BrokenPipeError:
        # Handle broken pipe when output is piped to head, grep, etc.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)
