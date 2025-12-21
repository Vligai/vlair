#!/usr/bin/env python3
"""
SecOps Helper - Central Control System
A unified security operations toolkit with automatic tool discovery and management.

Usage:
    secops                      # Interactive mode
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
SecOps Helper - Central Control System

Usage:
    secops                      Interactive mode
    secops list                 List all available tools
    secops info <tool>          Show detailed tool information
    secops search <keyword>     Search for tools
    secops <tool> [args]        Run a specific tool
    secops --help               Show this help message
    secops --version            Show version information

Available Tools:
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

Examples:
    secops                              # Start interactive menu
    secops list                         # List all tools
    secops info hash                    # Get info about hash tool
    secops eml suspicious.eml --vt      # Run email parser
    secops search malware               # Search for malware-related tools

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
        print("SecOps Helper v3.0.0")
        print("All 12 tools implemented - Phase 4 Complete")
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
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
