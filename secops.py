#!/usr/bin/env python3
"""
SecOps Helper - Central Control System
A unified security operations toolkit with automatic tool discovery and management.

Usage:
    secops                      # Interactive mode
    secops analyze <input>      # Smart analyze (auto-detect input type)
    secops check <type> <value> # Quick indicator lookup
    secops workflow <name> <in> # Run pre-built investigation workflow
    secops investigate          # Interactive guided investigation
    secops status               # Show system status dashboard
    secops list                 # List all available tools
    secops <tool> [args]        # Run a specific tool
    secops info <tool>          # Get detailed info about a tool
    secops search <keyword>     # Search for tools by keyword
"""

import sys
import os
import json
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse


class ToolDiscovery:
    """Automatically discover and catalog all available tools"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.tools = {}
        self._discover_tools()

    def _discover_tools(self):
        """Scan directories and discover all available tools"""

        # Define tool metadata
        tool_definitions = {
            'eml': {
                'name': 'EML Parser',
                'module': 'emlAnalysis.emlParser',
                'category': 'Email Analysis',
                'description': 'Parse and analyze email files (.eml) with attachment hashing and header analysis',
                'keywords': ['email', 'eml', 'phishing', 'attachment', 'header', 'spf', 'dkim', 'dmarc'],
                'examples': [
                    'secops eml suspicious.eml --vt',
                    'secops eml phishing.eml --output report.json'
                ],
                'requires_api': ['VT_API_KEY (optional)']
            },
            'ioc': {
                'name': 'IOC Extractor',
                'module': 'iocExtractor.extractor',
                'category': 'Threat Intelligence',
                'description': 'Extract indicators of compromise (IPs, domains, URLs, hashes, CVEs) from text',
                'keywords': ['ioc', 'indicator', 'ip', 'domain', 'url', 'hash', 'cve', 'extract'],
                'examples': [
                    'secops ioc threat_report.txt',
                    'secops ioc --file report.txt --format csv --defang'
                ],
                'requires_api': []
            },
            'hash': {
                'name': 'Hash Lookup',
                'module': 'hashLookup.lookup',
                'category': 'Threat Intelligence',
                'description': 'Look up file hashes against VirusTotal and MalwareBazaar',
                'keywords': ['hash', 'md5', 'sha1', 'sha256', 'virustotal', 'malware', 'threat'],
                'examples': [
                    'secops hash 44d88612fea8a8f36de82e1278abb02f',
                    'secops hash --file hashes.txt --verbose'
                ],
                'requires_api': ['VT_API_KEY (optional)']
            },
            'intel': {
                'name': 'Domain/IP Intelligence',
                'module': 'domainIpIntel.intel',
                'category': 'Threat Intelligence',
                'description': 'Analyze domains and IP addresses with threat intelligence and DNS resolution',
                'keywords': ['domain', 'ip', 'dns', 'whois', 'reputation', 'threat', 'intelligence'],
                'examples': [
                    'secops intel malicious.com',
                    'secops intel 1.2.3.4 --verbose'
                ],
                'requires_api': ['VT_API_KEY', 'ABUSEIPDB_KEY (optional)']
            },
            'log': {
                'name': 'Log Analyzer',
                'module': 'logAnalysis.analyzer',
                'category': 'Log Analysis',
                'description': 'Analyze Apache, Nginx, and syslog files for security threats',
                'keywords': ['log', 'apache', 'nginx', 'syslog', 'attack', 'web', 'security'],
                'examples': [
                    'secops log /var/log/apache2/access.log',
                    'secops log nginx.log --type nginx --format txt'
                ],
                'requires_api': []
            },
            'pcap': {
                'name': 'PCAP Analyzer',
                'module': 'pcapAnalyzer.analyzer',
                'category': 'Network Analysis',
                'description': 'Analyze network traffic captures for threats and anomalies',
                'keywords': ['pcap', 'network', 'traffic', 'packet', 'dns', 'http', 'scan'],
                'examples': [
                    'secops pcap capture.pcap',
                    'secops pcap traffic.pcapng --verbose --output analysis.json'
                ],
                'requires_api': []
            },
            'url': {
                'name': 'URL Analyzer',
                'module': 'urlAnalyzer.analyzer',
                'category': 'Threat Intelligence',
                'description': 'Analyze URLs for threats, phishing, and malware',
                'keywords': ['url', 'link', 'phishing', 'malware', 'suspicious', 'threat'],
                'examples': [
                    'secops url "http://suspicious-site.com"',
                    'secops url --file urls.txt --format json'
                ],
                'requires_api': ['VT_API_KEY (optional)']
            },
            'yara': {
                'name': 'YARA Scanner',
                'module': 'yaraScanner.scanner',
                'category': 'Malware Analysis',
                'description': 'Scan files and directories with YARA malware detection rules',
                'keywords': ['yara', 'malware', 'scan', 'signature', 'rule', 'detection'],
                'examples': [
                    'secops yara scan /samples/ --rules ./yaraScanner/rules/',
                    'secops yara scan malware.exe --rules custom.yar'
                ],
                'requires_api': []
            },
            'cert': {
                'name': 'Certificate Analyzer',
                'module': 'certAnalyzer.analyzer',
                'category': 'SSL/TLS Analysis',
                'description': 'Analyze SSL/TLS certificates for security issues and phishing',
                'keywords': ['certificate', 'ssl', 'tls', 'https', 'x509', 'phishing', 'crypto'],
                'examples': [
                    'secops cert https://example.com',
                    'secops cert --file cert.pem --hostname example.com'
                ],
                'requires_api': []
            },
            'deobfuscate': {
                'name': 'Script Deobfuscator',
                'module': 'deobfuscator.deobfuscator',
                'category': 'Malware Analysis',
                'description': 'Deobfuscate PowerShell, JavaScript, VBScript, and other malicious scripts',
                'keywords': ['deobfuscate', 'powershell', 'javascript', 'vbscript', 'decode', 'base64'],
                'examples': [
                    'secops deobfuscate malware.js --extract-iocs',
                    'secops deobfuscate script.ps1 --language powershell'
                ],
                'requires_api': []
            },
            'threatfeed': {
                'name': 'Threat Feed Aggregator',
                'module': 'threatFeedAggregator.aggregator',
                'category': 'Threat Intelligence',
                'description': 'Aggregate and manage threat intelligence feeds from multiple sources',
                'keywords': ['threat', 'feed', 'ioc', 'aggregator', 'threatfox', 'urlhaus'],
                'examples': [
                    'secops threatfeed update --source all',
                    'secops threatfeed search --type domain --confidence 80'
                ],
                'requires_api': []
            },
            'carve': {
                'name': 'File Carver',
                'module': 'fileCarver.carver',
                'category': 'Forensics',
                'description': 'Extract embedded files from disk images, memory dumps, and binary files',
                'keywords': ['carve', 'forensics', 'extract', 'file', 'disk', 'memory', 'dump'],
                'examples': [
                    'secops carve --image disk.dd --output /carved/',
                    'secops carve --image memdump.raw --types exe,dll,pdf'
                ],
                'requires_api': []
            }
        }

        # Verify and register tools
        for tool_id, metadata in tool_definitions.items():
            module_path = self.base_dir / (metadata['module'].replace('.', '/') + '.py')
            if module_path.exists():
                self.tools[tool_id] = metadata
                self.tools[tool_id]['available'] = True
                self.tools[tool_id]['path'] = str(module_path)
            else:
                self.tools[tool_id] = metadata
                self.tools[tool_id]['available'] = False

    def get_tool(self, tool_id: str) -> Optional[Dict]:
        """Get tool metadata by ID"""
        return self.tools.get(tool_id)

    def get_all_tools(self) -> Dict:
        """Get all discovered tools"""
        return self.tools

    def get_by_category(self, category: str) -> List[Tuple[str, Dict]]:
        """Get tools by category"""
        return [(tid, tool) for tid, tool in self.tools.items()
                if tool['category'] == category]

    def search_tools(self, keyword: str) -> List[Tuple[str, Dict]]:
        """Search tools by keyword"""
        keyword = keyword.lower()
        results = []

        for tool_id, tool in self.tools.items():
            # Search in name, description, and keywords
            if (keyword in tool['name'].lower() or
                keyword in tool['description'].lower() or
                any(keyword in kw.lower() for kw in tool['keywords'])):
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
            print(f"Run 'secops list' to see available tools", file=sys.stderr)
            sys.exit(1)

        if not tool['available']:
            print(f"Error: Tool '{tool_id}' not found at {tool.get('path', 'unknown path')}",
                  file=sys.stderr)
            sys.exit(1)

        # Import and run the tool
        try:
            module_name = tool['module']
            parts = module_name.split('.')

            # Dynamically import the module
            module_path = Path(__file__).parent / parts[0] / f"{parts[1]}.py"
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)

            # Set up argv for the tool
            sys.argv = [parts[1] + '.py'] + args

            # Execute
            spec.loader.exec_module(module)
            if hasattr(module, 'main'):
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
        print("\n" + "="*70)
        print("  SecOps Helper - Security Operations Toolkit")
        print("="*70)
        print("\nWhat would you like to do?\n")
        print("  1. Browse tools by category")
        print("  2. Search for a tool")
        print("  3. List all tools")
        print("  4. View API key status")
        print("  5. Quick start guide")
        print("  0. Exit")
        print("\n" + "-"*70)

        choice = input("\nEnter your choice (0-5): ").strip()

        if choice == '1':
            self.browse_by_category()
        elif choice == '2':
            self.search_tools()
        elif choice == '3':
            self.list_all_tools()
        elif choice == '4':
            self.show_api_status()
        elif choice == '5':
            self.show_quick_start()
        elif choice == '0':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please try again.")
            self.show_main_menu()

    def browse_by_category(self):
        """Browse tools by category"""
        # Get all unique categories
        categories = sorted(set(tool['category'] for tool in self.discovery.get_all_tools().values()))

        print("\n" + "="*70)
        print("  Tool Categories")
        print("="*70 + "\n")

        for i, category in enumerate(categories, 1):
            tools_in_category = self.discovery.get_by_category(category)
            print(f"  {i}. {category} ({len(tools_in_category)} tools)")

        print("  0. Back to main menu")
        print("\n" + "-"*70)

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

        print("\n" + "="*70)
        print(f"  {category} Tools")
        print("="*70 + "\n")

        for i, (tool_id, tool) in enumerate(tools, 1):
            status = "✓" if tool['available'] else "✗"
            print(f"  {i}. [{status}] {tool['name']}")
            print(f"      {tool['description']}")
            print()

        print("  i. Get info on a tool")
        print("  0. Back")
        print("\n" + "-"*70)

        choice = input("\nEnter choice: ").strip()

        if choice == '0':
            self.browse_by_category()
        elif choice.lower() == 'i':
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

        print("\n" + "="*70)
        print(f"  Search Results for '{keyword}'")
        print("="*70 + "\n")

        if not results:
            print(f"  No tools found matching '{keyword}'\n")
        else:
            for tool_id, tool in results:
                status = "✓" if tool['available'] else "✗"
                print(f"  [{status}] {tool['name']} ({tool_id})")
                print(f"      Category: {tool['category']}")
                print(f"      {tool['description']}")
                print()

        input("\nPress Enter to continue...")
        self.show_main_menu()

    def list_all_tools(self):
        """List all available tools"""
        print("\n" + "="*70)
        print("  All Available Tools")
        print("="*70 + "\n")

        tools = sorted(self.discovery.get_all_tools().items(),
                      key=lambda x: x[1]['category'])

        current_category = None
        for tool_id, tool in tools:
            if tool['category'] != current_category:
                current_category = tool['category']
                print(f"\n  {current_category}:")
                print("  " + "-" * 40)

            status = "✓" if tool['available'] else "✗"
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

        print("\n" + "="*70)
        print(f"  {tool['name']}")
        print("="*70)
        print(f"\nCommand ID: {tool_id}")
        print(f"Category:   {tool['category']}")
        print(f"Status:     {'Available ✓' if tool['available'] else 'Not Found ✗'}")
        print(f"\nDescription:")
        print(f"  {tool['description']}")

        if tool['keywords']:
            print(f"\nKeywords: {', '.join(tool['keywords'])}")

        if tool['requires_api']:
            print(f"\nAPI Keys Required:")
            for api_key in tool['requires_api']:
                status = "✓" if os.getenv(api_key.split()[0]) else "✗"
                print(f"  [{status}] {api_key}")

        if tool['examples']:
            print(f"\nUsage Examples:")
            for example in tool['examples']:
                print(f"  $ {example}")

        print("\n" + "-"*70)
        input("\nPress Enter to continue...")

    def show_api_status(self):
        """Show status of API keys"""
        print("\n" + "="*70)
        print("  API Key Status")
        print("="*70 + "\n")

        api_keys = {
            'VT_API_KEY': 'VirusTotal API Key',
            'ABUSEIPDB_KEY': 'AbuseIPDB API Key',
            'THREATFOX_API_KEY': 'ThreatFox API Key (optional)',
            'URLHAUS_API_KEY': 'URLHaus API Key (optional)'
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
        print("\n" + "="*70)
        print("  Quick Start Guide")
        print("="*70)
        print("""
1. Basic Usage:

   Interactive Mode:
     $ secops

   Direct Command:
     $ secops <tool> [arguments]

   List All Tools:
     $ secops list

   Get Tool Info:
     $ secops info <tool>

2. Common Workflows:

   Analyze Suspicious Email:
     $ secops eml suspicious.eml --vt --output report.json

   Extract IOCs from Threat Report:
     $ secops ioc report.txt --format csv --output iocs.csv

   Check Hash Reputation:
     $ secops hash <md5/sha1/sha256>

   Analyze Domain/IP:
     $ secops intel malicious.com

   Scan for Malware:
     $ secops yara scan /path/to/files --rules ./yaraScanner/rules/

3. Configuration:

   Create .env file with API keys:
     VT_API_KEY=your_virustotal_key
     ABUSEIPDB_KEY=your_abuseipdb_key

4. Get Help:

   General Help:
     $ secops --help

   Tool-Specific Help:
     $ secops <tool> --help

5. Advanced Features:

   - Batch processing with --file option
   - Multiple output formats (JSON, CSV, TXT)
   - Caching for improved performance
   - STIX 2.1 export support
        """)

        input("\nPress Enter to continue...")
        self.show_main_menu()


def print_usage():
    """Print usage information"""
    print("""
SecOps Helper - Security Operations Toolkit

Quick Start:
    secops analyze <input>      Auto-detect and analyze (RECOMMENDED)

The 'analyze' command automatically detects what you're analyzing and runs
the appropriate tools. Just give it a file, hash, IP, domain, or URL.

Usage:
    secops analyze <input>      Smart analysis (auto-detect input type)
    secops workflow <name> <input>  Run pre-built investigation workflow
    secops investigate          Guided interactive investigation mode
    secops status               Show API key and tool status
    secops                      Tool browser (interactive menu)
    secops list                 List all available tools
    secops info <tool>          Show detailed tool information
    secops search <keyword>     Search for tools
    secops <tool> [args]        Run a specific tool directly
    secops --help               Show this help message
    secops --version            Show version information

Examples - Smart Analyze:
    secops analyze suspicious.eml           # Analyze email file
    secops analyze 44d88612fea8a8f36...     # Check hash reputation
    secops analyze malicious.com            # Get domain intelligence
    secops analyze capture.pcap             # Analyze network traffic

Examples - Workflows:
    secops workflow phishing-email suspicious.eml   # Full phishing investigation
    secops workflow malware-triage sample.exe       # Malware analysis
    secops workflow ioc-hunt indicators.txt         # Bulk IOC hunting
    secops workflow network-forensics capture.pcap  # PCAP forensics
    secops workflow log-investigation access.log    # Log analysis

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
    """)


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

    elif sys.argv[1] in ['--help', '-h', 'help']:
        print_usage()
        sys.exit(0)

    elif sys.argv[1] in ['--version', '-v']:
        print("SecOps Helper v4.0.0")
        print("Phase 5: Operationalization - Smart analyze command")
        sys.exit(0)

    elif sys.argv[1] == 'list':
        # List all tools
        tools = sorted(discovery.get_all_tools().items(),
                      key=lambda x: x[1]['category'])

        print("\nAvailable Tools:\n")
        current_category = None
        for tool_id, tool in tools:
            if tool['category'] != current_category:
                current_category = tool['category']
                print(f"\n{current_category}:")
                print("-" * 40)

            status = "✓" if tool['available'] else "✗"
            print(f"  [{status}] {tool_id:12s} - {tool['name']}")

        print("\nUse 'secops info <tool>' for detailed information")
        print("Use 'secops <tool> --help' for usage help\n")

    elif sys.argv[1] == 'info':
        if len(sys.argv) < 3:
            print("Usage: secops info <tool>", file=sys.stderr)
            sys.exit(1)

        tool_id = sys.argv[2]
        tool = discovery.get_tool(tool_id)

        if not tool:
            print(f"Error: Unknown tool '{tool_id}'", file=sys.stderr)
            print("Run 'secops list' to see available tools", file=sys.stderr)
            sys.exit(1)

        menu.show_tool_info(tool_id)

    elif sys.argv[1] == 'search':
        if len(sys.argv) < 3:
            print("Usage: secops search <keyword>", file=sys.stderr)
            sys.exit(1)

        keyword = sys.argv[2]
        results = discovery.search_tools(keyword)

        print(f"\nSearch Results for '{keyword}':\n")

        if not results:
            print(f"No tools found matching '{keyword}'\n")
        else:
            for tool_id, tool in results:
                status = "✓" if tool['available'] else "✗"
                print(f"  [{status}] {tool_id:12s} - {tool['name']}")
                print(f"      {tool['description']}\n")

    elif sys.argv[1] == 'analyze':
        # Smart analyze command - auto-detect and run appropriate tools
        if len(sys.argv) < 3:
            print("Usage: secops analyze <input> [--verbose] [--json] [--quiet]", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  secops analyze suspicious.eml     # Auto-detect email", file=sys.stderr)
            print("  secops analyze 44d88612...        # Auto-detect hash", file=sys.stderr)
            print("  secops analyze malicious.com      # Auto-detect domain", file=sys.stderr)
            print("  secops analyze 192.168.1.1        # Auto-detect IP", file=sys.stderr)
            sys.exit(1)

        try:
            import time as _time
            _analyze_start = _time.time()

            from core.analyzer import Analyzer
            from core.reporter import Reporter

            # Parse analyze arguments
            input_value = sys.argv[2]
            verbose = '--verbose' in sys.argv or '-v' in sys.argv[3:]
            json_output = '--json' in sys.argv or '-j' in sys.argv
            quiet = '--quiet' in sys.argv or '-q' in sys.argv

            # Parse report arguments
            report_format = None
            output_path = None
            args_list = sys.argv[3:]
            for i, arg in enumerate(args_list):
                if arg == '--report':
                    if i + 1 < len(args_list) and args_list[i + 1] in ('html', 'markdown', 'md'):
                        report_format = args_list[i + 1]
                    else:
                        report_format = 'html'
                if arg in ('--output', '-o'):
                    if i + 1 < len(args_list):
                        output_path = args_list[i + 1]

            # Run analysis
            analyzer = Analyzer(verbose=verbose)
            result = analyzer.analyze(input_value)

            # Format output
            reporter = Reporter()

            if quiet:
                print(reporter.format_quiet(result['scorer']))
            elif json_output:
                print(reporter.format_json(
                    result['input'],
                    result['type'],
                    result['scorer'],
                    result['iocs'],
                    result['tool_results']
                ))
            elif verbose:
                print(reporter.format_verbose(
                    result['input'],
                    result['type'],
                    result['scorer'],
                    result['iocs'],
                    result['tool_results']
                ))
            else:
                print(reporter.format_console(
                    result['input'],
                    result['type'],
                    result['scorer'],
                    result['iocs'],
                    result['tool_results']
                ))

            # Generate report if requested
            if report_format:
                from core.report_generator import ReportGenerator
                generator = ReportGenerator()
                report_path = generator.generate(result, report_format, output_path)
                print(f"\nReport saved to: {report_path}", file=sys.stderr)

            # Record in history
            try:
                from core.history import AnalysisHistory
                history = AnalysisHistory()
                scorer = result['scorer']
                history.record(
                    input_value=input_value,
                    input_type=result['type'],
                    verdict=scorer.get_summary().get('verdict', 'UNKNOWN'),
                    risk_score=scorer.get_summary().get('risk_score'),
                    command='analyze',
                    duration_seconds=_time.time() - _analyze_start
                )
            except Exception:
                pass

            sys.exit(reporter.get_exit_code(result['scorer']))

        except ImportError as e:
            print(f"Error: Could not load analyzer module: {e}", file=sys.stderr)
            print("Make sure core/ directory exists with analyzer.py", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during analysis: {e}", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == 'check':
        # Quick indicator lookup - direct tool invocation without full analysis pipeline
        if len(sys.argv) < 3:
            print("Usage: secops check <type> <value> [--json] [--verbose]", file=sys.stderr)
            print("       secops check <file>          # Auto-detect IOC file", file=sys.stderr)
            print("\nTypes:", file=sys.stderr)
            print("  hash    <hash>     Look up a file hash (MD5/SHA1/SHA256)", file=sys.stderr)
            print("  domain  <domain>   Get domain intelligence", file=sys.stderr)
            print("  ip      <ip>       Get IP intelligence", file=sys.stderr)
            print("  url     <url>      Check URL reputation", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  secops check hash 44d88612fea8a8f36de82e1278abb02f", file=sys.stderr)
            print("  secops check domain malicious.com", file=sys.stderr)
            print("  secops check ip 1.2.3.4 --json", file=sys.stderr)
            print("  secops check url http://bad.com/payload", file=sys.stderr)
            print("  secops check iocs.txt", file=sys.stderr)
            sys.exit(1)

        check_type = sys.argv[2]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv[3:]
        json_output = '--json' in sys.argv or '-j' in sys.argv

        try:
            import time as _time
            start_time = _time.time()

            # Known type keywords route directly to tools
            if check_type == 'hash':
                if len(sys.argv) < 4:
                    print("Error: Missing hash value", file=sys.stderr)
                    print("Usage: secops check hash <md5|sha1|sha256>", file=sys.stderr)
                    sys.exit(1)
                hash_value = sys.argv[3]
                from hashLookup.lookup import HashLookup
                lookup = HashLookup(verbose=verbose)
                result = lookup.lookup(hash_value)
                indicator_type = 'hash'

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get('verdict', 'UNKNOWN')
                    detections = result.get('detections', 0)
                    total = result.get('total_engines', 0)
                    print(f"Hash: {hash_value}")
                    print(f"Verdict: {verdict}")
                    if detections or total:
                        print(f"Detections: {detections}/{total}")
                    malware_family = result.get('malware_family') or result.get('suggested_threat_label')
                    if malware_family:
                        print(f"Family: {malware_family}")
                    sources = result.get('sources', [])
                    if sources:
                        print(f"Sources: {', '.join(sources)}")

            elif check_type == 'domain':
                if len(sys.argv) < 4:
                    print("Error: Missing domain value", file=sys.stderr)
                    print("Usage: secops check domain <domain>", file=sys.stderr)
                    sys.exit(1)
                domain_value = sys.argv[3]
                from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel
                intel = DomainIPIntel(verbose=verbose)
                result = intel.lookup(domain_value)
                indicator_type = 'domain'

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get('verdict', 'UNKNOWN')
                    risk_score = result.get('risk_score', 0)
                    print(f"Domain: {domain_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    dns = result.get('dns', {})
                    if dns.get('a_records'):
                        print(f"IPs: {', '.join(dns['a_records'][:5])}")
                    categories = result.get('categories', [])
                    if categories:
                        print(f"Categories: {', '.join(categories[:5])}")

            elif check_type == 'ip':
                if len(sys.argv) < 4:
                    print("Error: Missing IP address", file=sys.stderr)
                    print("Usage: secops check ip <ip_address>", file=sys.stderr)
                    sys.exit(1)
                ip_value = sys.argv[3]
                from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel
                intel = DomainIPIntel(verbose=verbose)
                result = intel.lookup(ip_value)
                indicator_type = 'ip'

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get('verdict', 'UNKNOWN')
                    risk_score = result.get('risk_score', 0)
                    print(f"IP: {ip_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    abuse_score = result.get('abuse_confidence_score')
                    if abuse_score is not None:
                        print(f"Abuse Score: {abuse_score}%")
                    country = result.get('country')
                    if country:
                        print(f"Country: {country}")

            elif check_type == 'url':
                if len(sys.argv) < 4:
                    print("Error: Missing URL", file=sys.stderr)
                    print("Usage: secops check url <url>", file=sys.stderr)
                    sys.exit(1)
                url_value = sys.argv[3]
                from urlAnalyzer.analyzer import URLAnalyzer
                analyzer = URLAnalyzer(verbose=verbose)
                result = analyzer.analyze(url_value)
                indicator_type = 'url'

                if json_output:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    verdict = result.get('verdict', 'UNKNOWN')
                    risk_score = result.get('risk_score', 0)
                    print(f"URL: {url_value}")
                    print(f"Verdict: {verdict}")
                    print(f"Risk Score: {risk_score}/100")
                    threats = result.get('threats', [])
                    if threats:
                        for threat in threats[:5]:
                            print(f"  [!] {threat}")

            elif os.path.isfile(check_type):
                # Auto-detect file as IOC list
                from core.analyzer import Analyzer
                from core.reporter import Reporter

                analyzer_instance = Analyzer(verbose=verbose)
                result = analyzer_instance.analyze(check_type)
                indicator_type = result.get('type', 'file')

                reporter = Reporter()
                if json_output:
                    print(reporter.format_json(
                        result['input'], result['type'],
                        result['scorer'], result['iocs'], result['tool_results']
                    ))
                else:
                    print(reporter.format_console(
                        result['input'], result['type'],
                        result['scorer'], result['iocs'], result['tool_results']
                    ))
                sys.exit(reporter.get_exit_code(result['scorer']))

            else:
                print(f"Error: Unknown check type '{check_type}'", file=sys.stderr)
                print("Valid types: hash, domain, ip, url", file=sys.stderr)
                print("Or provide a file path for batch IOC checking", file=sys.stderr)
                sys.exit(1)

            # Record in history
            duration = _time.time() - start_time
            try:
                from core.history import AnalysisHistory
                history = AnalysisHistory()
                verdict_val = result.get('verdict', 'UNKNOWN') if isinstance(result, dict) else 'UNKNOWN'
                score_val = result.get('risk_score') if isinstance(result, dict) else None
                history.record(
                    input_value=sys.argv[3] if len(sys.argv) > 3 else check_type,
                    input_type=indicator_type,
                    verdict=verdict_val,
                    risk_score=score_val,
                    command='check',
                    duration_seconds=duration
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

    elif sys.argv[1] == 'workflow':
        # Pre-built investigation workflows
        if len(sys.argv) < 3:
            print("Usage: secops workflow <name> <input> [--verbose] [--json]", file=sys.stderr)
            print("\nAvailable workflows:", file=sys.stderr)
            print("  phishing-email     Comprehensive phishing email investigation", file=sys.stderr)
            print("  malware-triage     Quick malware analysis and triage", file=sys.stderr)
            print("  ioc-hunt           Bulk IOC threat hunting", file=sys.stderr)
            print("  network-forensics  Network traffic forensic analysis", file=sys.stderr)
            print("  log-investigation  Security log investigation", file=sys.stderr)
            print("\nExamples:", file=sys.stderr)
            print("  secops workflow phishing-email suspicious.eml", file=sys.stderr)
            print("  secops workflow malware-triage sample.exe --verbose", file=sys.stderr)
            print("  secops workflow ioc-hunt iocs.txt --json", file=sys.stderr)
            sys.exit(1)

        workflow_name = sys.argv[2]

        if len(sys.argv) < 4:
            print(f"Error: Missing input for workflow '{workflow_name}'", file=sys.stderr)
            print(f"Usage: secops workflow {workflow_name} <input>", file=sys.stderr)
            sys.exit(1)

        input_value = sys.argv[3]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv[4:]
        json_output = '--json' in sys.argv or '-j' in sys.argv

        # Parse report arguments
        report_format = None
        output_path = None
        args_list = sys.argv[4:]
        for i, arg in enumerate(args_list):
            if arg == '--report':
                if i + 1 < len(args_list) and args_list[i + 1] in ('html', 'markdown', 'md'):
                    report_format = args_list[i + 1]
                else:
                    report_format = 'html'
            if arg in ('--output', '-o'):
                if i + 1 < len(args_list):
                    output_path = args_list[i + 1]

        try:
            from core.workflow import WorkflowRegistry
            from core.reporter import Reporter

            # Import workflows to register them
            from workflows import (
                PhishingEmailWorkflow,
                MalwareTriageWorkflow,
                IOCHuntWorkflow,
                NetworkForensicsWorkflow,
                LogInvestigationWorkflow
            )

            # Get workflow class
            workflow_class = WorkflowRegistry.get(workflow_name)
            if not workflow_class:
                print(f"Error: Unknown workflow '{workflow_name}'", file=sys.stderr)
                print("Run 'secops workflow' to see available workflows", file=sys.stderr)
                sys.exit(1)

            # Execute workflow
            workflow_instance = workflow_class(verbose=verbose)
            result = workflow_instance.execute(input_value)

            # Generate report before potentially modifying result for JSON output
            if report_format:
                from core.report_generator import ReportGenerator
                generator = ReportGenerator()
                report_path = generator.generate(result, report_format, output_path)
                print(f"\nReport saved to: {report_path}", file=sys.stderr)

            # Format output
            reporter = Reporter()

            if json_output:
                # Convert scorer to summary for JSON
                result['summary'] = result['scorer'].get_summary()
                result['findings'] = result['scorer'].get_findings()
                result['recommendations'] = result['scorer'].get_recommendations()
                del result['scorer']
                print(json.dumps(result, indent=2, default=str))
            else:
                # Console output
                print(reporter.format_console(
                    result['input'],
                    result['type'],
                    result['scorer'],
                    result['iocs'],
                    result['tool_results']
                ))

                # Print workflow-specific info
                print(f"\nWorkflow: {result['workflow']}")
                print(f"Steps completed: {result['steps_completed']}/{result['steps_total']}")
                print(f"Duration: {result['duration_seconds']:.1f}s")

            sys.exit(reporter.get_exit_code(result['scorer']) if 'scorer' in result else 0)

        except ImportError as e:
            print(f"Error: Could not load workflow module: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during workflow execution: {e}", file=sys.stderr)
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    elif sys.argv[1] == 'investigate':
        # Interactive investigation mode
        try:
            from core.interactive import InteractiveInvestigation

            investigation = InteractiveInvestigation()
            investigation.run()
            sys.exit(0)

        except ImportError as e:
            print(f"Error: Could not load interactive module: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during investigation: {e}", file=sys.stderr)
            sys.exit(1)

    elif sys.argv[1] == 'status':
        # Quick status dashboard
        print("\nSecOps Helper Status Dashboard")
        print("=" * 50)

        # Check API keys
        from dotenv import load_dotenv
        load_dotenv()

        api_keys = {
            'VT_API_KEY': 'VirusTotal',
            'ABUSEIPDB_KEY': 'AbuseIPDB',
            'THREATFOX_API_KEY': 'ThreatFox',
            'URLHAUS_API_KEY': 'URLhaus'
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
            'EML Parser': base_path / 'emlAnalysis' / 'emlParser.py',
            'IOC Extractor': base_path / 'iocExtractor' / 'extractor.py',
            'Hash Lookup': base_path / 'hashLookup' / 'lookup.py',
            'Domain/IP Intel': base_path / 'domainIpIntel' / 'intel.py',
            'Log Analyzer': base_path / 'logAnalysis' / 'analyzer.py',
            'PCAP Analyzer': base_path / 'pcapAnalyzer' / 'analyzer.py',
            'URL Analyzer': base_path / 'urlAnalyzer' / 'analyzer.py',
            'YARA Scanner': base_path / 'yaraScanner' / 'scanner.py',
            'Cert Analyzer': base_path / 'certAnalyzer' / 'analyzer.py',
            'Deobfuscator': base_path / 'deobfuscator' / 'deobfuscator.py',
            'Threat Feeds': base_path / 'threatFeedAggregator' / 'aggregator.py',
            'File Carver': base_path / 'fileCarver' / 'carver.py',
        }

        available_count = sum(1 for p in tool_files.values() if p.exists())
        print(f"\nTools: {available_count}/{len(tool_files)} available")

        # Cache statistics
        print("\nCache:")
        try:
            from common.cache_manager import get_cache
            cache = get_cache()
            print(f"  Backend: {cache.backend}")
            print(f"  Session stats - Hits: {cache.stats['hits']}, "
                  f"Misses: {cache.stats['misses']}, "
                  f"Sets: {cache.stats['sets']}")
        except Exception:
            print("  Not available")

        # Threat feed freshness
        print("\nThreat Feeds:")
        try:
            feeds_db = Path.home() / '.threatFeedAggregator' / 'feeds.db'
            if feeds_db.exists():
                import sqlite3
                conn = sqlite3.connect(str(feeds_db))
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM iocs')
                ioc_count = cursor.fetchone()[0]
                cursor.execute('SELECT MAX(last_seen) FROM iocs')
                last_update = cursor.fetchone()[0]
                conn.close()
                print(f"  IOCs in database: {ioc_count}")
                print(f"  Last updated: {last_update or 'Never'}")
            else:
                print("  Database not initialized (run: secops feeds update)")
        except Exception:
            print("  Not available")

        # Recent analysis history
        print("\nRecent Analyses:")
        try:
            from core.history import AnalysisHistory
            history = AnalysisHistory()
            stats = history.get_stats()

            if stats['total_analyses'] > 0:
                print(f"  Total: {stats['total_analyses']}")
                if stats['verdicts']:
                    verdict_str = ', '.join(f"{v}: {c}" for v, c in stats['verdicts'].items())
                    print(f"  Verdicts: {verdict_str}")
                if stats['last_analysis']:
                    print(f"  Last: {stats['last_analysis']}")

                # Show last 5 analyses
                recent = history.get_recent(5)
                if recent:
                    print("\n  Last 5:")
                    for entry in recent:
                        verdict = entry.get('verdict', '?')
                        score = entry.get('risk_score')
                        score_str = f" ({score}/100)" if score is not None else ""
                        ts = entry['timestamp'][:16].replace('T', ' ')
                        inp = entry['input_value']
                        if len(inp) > 30:
                            inp = inp[:27] + '...'
                        print(f"    {ts}  {inp:30s}  {verdict}{score_str}")
            else:
                print("  No analyses recorded yet")
        except Exception:
            print("  History not available")

        # Features summary
        print("\nFeatures:")
        print("  [+] Smart analyze command (secops analyze)")
        print("  [+] Quick check command (secops check)")
        print("  [+] Pre-built workflows (5)")
        print("  [+] Interactive investigation mode")
        print("  [+] Report generation (HTML/Markdown)")
        print()

    else:
        # Run a tool
        tool_id = sys.argv[1]
        tool_args = sys.argv[2:]

        manager.run_tool(tool_id, tool_args)


if __name__ == '__main__':
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
