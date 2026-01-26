#!/usr/bin/env python3
"""
SecOps Helper - Unified CLI for Security Operations Tools

A comprehensive toolkit for security analysts providing unified access to:
- Email analysis (EML parser)
- IOC extraction
- Hash threat intelligence
- Domain/IP intelligence
- Log analysis
- PCAP network analysis
- URL threat analysis
- YARA malware scanning
- SSL/TLS certificate analysis
- Script deobfuscation
"""

import sys
import argparse
from pathlib import Path


def create_parser():
    """Create the main argument parser"""
    parser = argparse.ArgumentParser(
        prog="secops-helper",
        description="SecOps Helper - Security Operations Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Commands:
  eml          Parse and analyze email files (.eml)
  ioc          Extract indicators of compromise from text
  hash         Look up file hashes against threat intelligence
  intel        Analyze domains and IP addresses
  log          Analyze security logs for threats
  pcap         Analyze network traffic captures
  url          Analyze URLs for threats and reputation
  yara         Scan files with YARA malware detection rules
  cert         Analyze SSL/TLS certificates for security issues
  deobfuscate  Deobfuscate malicious scripts (PowerShell, JavaScript, etc.)

Examples:
  # Email analysis with VirusTotal
  secops-helper eml suspicious_email.eml --vt --output report.json

  # Extract IOCs from threat report
  secops-helper ioc threat_report.txt --format csv --output iocs.csv

  # Batch hash lookup
  secops-helper hash --file hashes.txt --verbose

  # Domain reputation check
  secops-helper intel malicious.com --format json

  # Analyze Apache logs
  secops-helper log /var/log/apache2/access.log --format txt

  # PCAP analysis
  secops-helper pcap capture.pcap --verbose --output analysis.json

  # URL threat analysis
  secops-helper url "http://suspicious-site.com" --format txt

  # YARA malware scanning
  secops-helper yara scan /samples/ --rules ./yaraScanner/rules/ --recursive

  # Certificate analysis
  secops-helper cert https://example.com

  # Deobfuscate malicious script
  secops-helper deobfuscate malware.js --extract-iocs

For detailed help on each command:
  secops-helper <command> --help

Documentation: https://github.com/Vligai/secops-helper
        """,
    )

    parser.add_argument("--version", action="version", version="SecOps Helper v2.0.0")

    subparsers = parser.add_subparsers(
        dest="command", title="commands", description="Available security operations tools", help="Tool to run"
    )

    # EML Parser subcommand
    eml_parser = subparsers.add_parser(
        "eml", help="Parse and analyze email files", description="Extract metadata, headers, and attachments from .eml files"
    )
    eml_parser.add_argument("eml", help="Path to .eml file")
    eml_parser.add_argument("--output", "-o", help="Output file (JSON)")
    eml_parser.add_argument("--vt", action="store_true", help="Enable VirusTotal scanning")
    eml_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # IOC Extractor subcommand
    ioc_parser = subparsers.add_parser(
        "ioc", help="Extract indicators of compromise", description="Extract IPs, domains, URLs, hashes, and CVEs from text"
    )
    ioc_parser.add_argument("input", nargs="?", help="Input file or text")
    ioc_parser.add_argument("--file", "-f", help="Input file")
    ioc_parser.add_argument("--output", "-o", help="Output file")
    ioc_parser.add_argument("--format", choices=["json", "csv", "txt", "stix"], default="json", help="Output format")
    ioc_parser.add_argument("--types", nargs="+", help="IOC types to extract")
    ioc_parser.add_argument("--refang", action="store_true", help="Refang defanged IOCs")
    ioc_parser.add_argument("--defang", action="store_true", help="Defang output")
    ioc_parser.add_argument("--exclude-private", action="store_true", help="Exclude private IPs")

    # Hash Lookup subcommand
    hash_parser = subparsers.add_parser(
        "hash", help="Look up file hashes", description="Query threat intelligence for file hash reputation"
    )
    hash_parser.add_argument("hash", nargs="?", help="Hash to lookup")
    hash_parser.add_argument("--file", "-f", help="File with hashes (one per line)")
    hash_parser.add_argument("--output", "-o", help="Output file")
    hash_parser.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Output format")
    hash_parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    hash_parser.add_argument("--rate-limit", type=int, default=4, help="Requests per minute")
    hash_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Domain/IP Intel subcommand
    intel_parser = subparsers.add_parser(
        "intel", help="Analyze domains and IPs", description="Get threat intelligence for domains and IP addresses"
    )
    intel_parser.add_argument("target", nargs="?", help="IP address or domain")
    intel_parser.add_argument("--file", "-f", help="File with targets (one per line)")
    intel_parser.add_argument("--output", "-o", help="Output file")
    intel_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    intel_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Log Analyzer subcommand
    log_parser = subparsers.add_parser(
        "log", help="Analyze security logs", description="Parse and analyze Apache, Nginx, and syslog files"
    )
    log_parser.add_argument("log_file", help="Path to log file")
    log_parser.add_argument("--type", "-t", choices=["auto", "apache", "nginx", "syslog"], default="auto", help="Log type")
    log_parser.add_argument("--output", "-o", help="Output file")
    log_parser.add_argument("--format", "-f", choices=["json", "csv", "txt"], default="json", help="Output format")
    log_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # PCAP Analyzer subcommand
    pcap_parser = subparsers.add_parser(
        "pcap", help="Analyze network traffic", description="Analyze PCAP/PCAPNG files for threats and anomalies"
    )
    pcap_parser.add_argument("pcap_file", help="Path to PCAP file")
    pcap_parser.add_argument("--output", "-o", help="Output file")
    pcap_parser.add_argument("--format", "-f", choices=["json", "csv", "txt"], default="json", help="Output format")
    pcap_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # URL Analyzer subcommand
    url_parser = subparsers.add_parser(
        "url",
        help="Analyze URLs for threats",
        description="Check URLs against threat intelligence and detect suspicious patterns",
    )
    url_parser.add_argument("url", nargs="?", help="URL to analyze")
    url_parser.add_argument("--file", "-f", help="File with URLs (one per line)")
    url_parser.add_argument("--output", "-o", help="Output file")
    url_parser.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Output format")
    url_parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    url_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # YARA Scanner subcommand
    yara_parser = subparsers.add_parser(
        "yara", help="Scan files with YARA rules", description="Malware detection and pattern matching with YARA"
    )
    # YARA has its own subcommands, so we pass everything through
    yara_parser.add_argument(
        "yara_args", nargs=argparse.REMAINDER, help='YARA scanner arguments (use "secops-helper yara --help" for details)'
    )

    # Certificate Analyzer subcommand
    cert_parser = subparsers.add_parser(
        "cert",
        help="Analyze SSL/TLS certificates",
        description="Analyze certificates for security issues, phishing, and expiration",
    )
    cert_parser.add_argument("target", nargs="?", help="HTTPS URL or hostname")
    cert_parser.add_argument("--file", "-f", help="Certificate file (PEM or DER)")
    cert_parser.add_argument("--file-list", help="File with list of domains")
    cert_parser.add_argument("--hostname", help="Hostname for validation (with --file)")
    cert_parser.add_argument("--port", type=int, default=443, help="Port number")
    cert_parser.add_argument("--ct-search", help="Search Certificate Transparency logs")
    cert_parser.add_argument("--format", choices=["json", "txt"], default="txt", help="Output format")
    cert_parser.add_argument("--output", "-o", help="Output file")
    cert_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Deobfuscator subcommand
    deobf_parser = subparsers.add_parser(
        "deobfuscate",
        help="Deobfuscate malicious scripts",
        description="Deobfuscate PowerShell, JavaScript, VBScript, and other scripts",
    )
    deobf_parser.add_argument("input_file", nargs="?", help="Script file to deobfuscate")
    deobf_parser.add_argument(
        "--language",
        "-l",
        choices=["auto", "powershell", "javascript", "vbscript", "batch"],
        default="auto",
        help="Script language",
    )
    deobf_parser.add_argument("--max-layers", type=int, default=10, help="Maximum deobfuscation layers")
    deobf_parser.add_argument("--extract-iocs", action="store_true", help="Extract IOCs")
    deobf_parser.add_argument("--format", choices=["json", "txt"], default="txt", help="Output format")
    deobf_parser.add_argument("--output", "-o", help="Output file")
    deobf_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    deobf_parser.add_argument("--decode-base64", help="Decode base64 string directly")
    deobf_parser.add_argument("--decode-hex", help="Decode hex string directly")
    deobf_parser.add_argument("--decode-url", help="Decode URL-encoded string")

    return parser


def main():
    """Main entry point for SecOps Helper"""
    parser = create_parser()

    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Parse arguments
    args, remaining = parser.parse_known_args()

    # Route to appropriate tool
    if args.command == "eml":
        from emlAnalysis.emlParser import main as eml_main

        # Reconstruct argv for the tool
        sys.argv = ["emlParser.py", args.eml]
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.vt:
            sys.argv.append("--vt")
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        eml_main()

    elif args.command == "ioc":
        from iocExtractor.extractor import main as ioc_main

        # Reconstruct argv for the tool
        sys.argv = ["extractor.py"]
        if args.input:
            sys.argv.append(args.input)
        if args.file:
            sys.argv.extend(["--file", args.file])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.types:
            sys.argv.extend(["--types"] + args.types)
        if args.refang:
            sys.argv.append("--refang")
        if args.defang:
            sys.argv.append("--defang")
        if args.exclude_private:
            sys.argv.append("--exclude-private")
        sys.argv.extend(remaining)
        ioc_main()

    elif args.command == "hash":
        from hashLookup.lookup import main as hash_main

        # Reconstruct argv for the tool
        sys.argv = ["lookup.py"]
        if args.hash:
            sys.argv.append(args.hash)
        if args.file:
            sys.argv.extend(["--file", args.file])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.no_cache:
            sys.argv.append("--no-cache")
        if args.rate_limit:
            sys.argv.extend(["--rate-limit", str(args.rate_limit)])
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        hash_main()

    elif args.command == "intel":
        from domainIpIntel.intel import main as intel_main

        # Reconstruct argv for the tool
        sys.argv = ["intel.py"]
        if args.target:
            sys.argv.append(args.target)
        if args.file:
            sys.argv.extend(["--file", args.file])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        intel_main()

    elif args.command == "log":
        from logAnalysis.analyzer import main as log_main

        # Reconstruct argv for the tool
        sys.argv = ["analyzer.py", args.log_file]
        if args.type:
            sys.argv.extend(["--type", args.type])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        log_main()

    elif args.command == "pcap":
        from pcapAnalyzer.analyzer import main as pcap_main

        # Reconstruct argv for the tool
        sys.argv = ["analyzer.py", args.pcap_file]
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        pcap_main()

    elif args.command == "url":
        from urlAnalyzer.analyzer import main as url_main

        # Reconstruct argv for the tool
        sys.argv = ["analyzer.py"]
        if args.url:
            sys.argv.append(args.url)
        if args.file:
            sys.argv.extend(["--file", args.file])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.no_cache:
            sys.argv.append("--no-cache")
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        url_main()

    elif args.command == "yara":
        from yaraScanner.scanner import main as yara_main

        # Pass all arguments directly to YARA scanner
        sys.argv = ["scanner.py"] + args.yara_args + remaining
        yara_main()

    elif args.command == "cert":
        from certAnalyzer.analyzer import main as cert_main

        # Reconstruct argv for the tool
        sys.argv = ["analyzer.py"]
        if args.target:
            sys.argv.append(args.target)
        if args.file:
            sys.argv.extend(["--file", args.file])
        if args.file_list:
            sys.argv.extend(["--file-list", args.file_list])
        if args.hostname:
            sys.argv.extend(["--hostname", args.hostname])
        if args.port != 443:
            sys.argv.extend(["--port", str(args.port)])
        if args.ct_search:
            sys.argv.extend(["--ct-search", args.ct_search])
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.verbose:
            sys.argv.append("--verbose")
        sys.argv.extend(remaining)
        cert_main()

    elif args.command == "deobfuscate":
        from deobfuscator.deobfuscator import main as deobf_main

        # Reconstruct argv for the tool
        sys.argv = ["deobfuscator.py"]
        if args.input_file:
            sys.argv.append(args.input_file)
        if args.language != "auto":
            sys.argv.extend(["--language", args.language])
        if args.max_layers != 10:
            sys.argv.extend(["--max-layers", str(args.max_layers)])
        if args.extract_iocs:
            sys.argv.append("--extract-iocs")
        if args.format:
            sys.argv.extend(["--format", args.format])
        if args.output:
            sys.argv.extend(["--output", args.output])
        if args.verbose:
            sys.argv.append("--verbose")
        if args.decode_base64:
            sys.argv.extend(["--decode-base64", args.decode_base64])
        if args.decode_hex:
            sys.argv.extend(["--decode-hex", args.decode_hex])
        if args.decode_url:
            sys.argv.extend(["--decode-url", args.decode_url])
        sys.argv.extend(remaining)
        deobf_main()

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
