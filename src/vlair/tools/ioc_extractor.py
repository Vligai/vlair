#!/usr/bin/env python3
"""
IOC Extractor - Extract Indicators of Compromise from text sources
Supports IPs, domains, URLs, file hashes, emails, CVEs, and more
"""

import re
import sys
import json
import argparse
from collections import defaultdict, Counter
from typing import Dict, List, Set, Optional
from pathlib import Path
import hashlib


class IOCExtractor:
    """Extract various IOCs from text"""

    # Regex patterns for IOC extraction
    PATTERNS = {
        "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "ipv4_defanged": r"\b(?:[0-9]{1,3}\[\.\]){3}[0-9]{1,3}\b",
        "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
        "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        "domain_defanged": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[\.\])+[a-zA-Z]{2,}\b",
        "url": r'https?://[^\s<>"\']+',
        "url_defanged": r'hxxps?://[^\s<>"\']+',
        "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "email_defanged": r"\b[a-zA-Z0-9._%+-]+\[@\][a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}\b",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "sha512": r"\b[a-fA-F0-9]{128}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    }

    # Private IP ranges to filter (RFC 1918)
    PRIVATE_IP_PATTERNS = [
        r"^10\.",
        r"^192\.168\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^127\.",
        r"^169\.254\.",
    ]

    # Common legitimate domains to whitelist
    DEFAULT_WHITELIST_DOMAINS = {
        "localhost",
        "example.com",
        "example.org",
        "example.net",
        "microsoft.com",
        "apple.com",
        "google.com",
        "cloudflare.com",
    }

    def __init__(self, exclude_private_ips=False, whitelist_file=None, refang=False, defang=False):
        self.exclude_private_ips = exclude_private_ips
        self.refang = refang
        self.defang = defang
        self.whitelist_domains = self.DEFAULT_WHITELIST_DOMAINS.copy()

        if whitelist_file:
            self._load_whitelist(whitelist_file)

    def _load_whitelist(self, whitelist_file: str):
        """Load whitelist from file"""
        try:
            with open(whitelist_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.whitelist_domains.add(line.lower())
        except Exception as e:
            print(f"Warning: Could not load whitelist file: {e}", file=sys.stderr)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        for pattern in self.PRIVATE_IP_PATTERNS:
            if re.match(pattern, ip):
                return True
        return False

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _refang_text(self, text: str) -> str:
        """Convert defanged IOCs to active form"""
        text = text.replace("[.]", ".")
        text = text.replace("[@]", "@")
        text = re.sub(r"hxxps?://", lambda m: m.group(0).replace("hxxp", "http"), text)
        return text

    def _defang_ioc(self, ioc: str, ioc_type: str) -> str:
        """Convert active IOC to defanged form"""
        if ioc_type in ["ipv4", "domain", "url"]:
            ioc = ioc.replace(".", "[.]")
        if ioc_type == "url":
            ioc = ioc.replace("http://", "hxxp://")
            ioc = ioc.replace("https://", "hxxps://")
        if ioc_type == "email":
            ioc = ioc.replace("@", "[@]").replace(".", "[.]")
        return ioc

    def extract_from_text(self, text: str, types: Optional[List[str]] = None) -> Dict:
        """Extract IOCs from text"""
        if self.refang:
            text = self._refang_text(text)

        if types is None:
            types = ["ipv4", "domain", "url", "email", "hash", "cve"]

        results = {
            "ips": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "hashes": {"md5": [], "sha1": [], "sha256": [], "sha512": []},
            "cves": [],
        }

        # Extract IPs
        if "ip" in types or "ipv4" in types or "all" in types:
            ips = set()
            # Regular IPs
            for match in re.finditer(self.PATTERNS["ipv4"], text):
                ip = match.group(0)
                if self._is_valid_ip(ip):
                    if self.exclude_private_ips and self._is_private_ip(ip):
                        continue
                    ips.add(ip)

            # Defanged IPs
            for match in re.finditer(self.PATTERNS["ipv4_defanged"], text):
                ip = match.group(0).replace("[.]", ".")
                if self._is_valid_ip(ip):
                    if self.exclude_private_ips and self._is_private_ip(ip):
                        continue
                    ips.add(ip)

            results["ips"] = sorted(list(ips))

        # Extract domains
        if "domain" in types or "all" in types:
            domains = set()
            # Regular domains
            for match in re.finditer(self.PATTERNS["domain"], text):
                domain = match.group(0).lower()
                # Filter out IPs that match domain pattern
                if not self._is_valid_ip(domain) and domain not in self.whitelist_domains:
                    # Basic TLD validation
                    if "." in domain and len(domain.split(".")[-1]) >= 2:
                        domains.add(domain)

            # Defanged domains
            for match in re.finditer(self.PATTERNS["domain_defanged"], text):
                domain = match.group(0).replace("[.]", ".").lower()
                if domain not in self.whitelist_domains:
                    domains.add(domain)

            results["domains"] = sorted(list(domains))

        # Extract URLs
        if "url" in types or "all" in types:
            urls = set()
            # Regular URLs
            for match in re.finditer(self.PATTERNS["url"], text):
                urls.add(match.group(0))

            # Defanged URLs
            for match in re.finditer(self.PATTERNS["url_defanged"], text):
                url = match.group(0)
                if self.refang:
                    url = url.replace("hxxp://", "http://").replace("hxxps://", "https://")
                    url = url.replace("[.]", ".")
                urls.add(url)

            results["urls"] = sorted(list(urls))

        # Extract emails
        if "email" in types or "all" in types:
            emails = set()
            # Regular emails
            for match in re.finditer(self.PATTERNS["email"], text):
                emails.add(match.group(0).lower())

            # Defanged emails
            for match in re.finditer(self.PATTERNS["email_defanged"], text):
                email = match.group(0).replace("[@]", "@").replace("[.]", ".").lower()
                emails.add(email)

            results["emails"] = sorted(list(emails))

        # Extract hashes
        if "hash" in types or "all" in types:
            for hash_type in ["md5", "sha1", "sha256", "sha512"]:
                hashes = set()
                for match in re.finditer(self.PATTERNS[hash_type], text):
                    hashes.add(match.group(0).lower())
                results["hashes"][hash_type] = sorted(list(hashes))

        # Extract CVEs
        if "cve" in types or "all" in types:
            cves = set()
            for match in re.finditer(self.PATTERNS["cve"], text, re.IGNORECASE):
                cves.add(match.group(0).upper())
            results["cves"] = sorted(list(cves))

        # Apply defanging if requested
        if self.defang:
            results["ips"] = [self._defang_ioc(ip, "ipv4") for ip in results["ips"]]
            results["domains"] = [self._defang_ioc(d, "domain") for d in results["domains"]]
            results["urls"] = [self._defang_ioc(u, "url") for u in results["urls"]]
            results["emails"] = [self._defang_ioc(e, "email") for e in results["emails"]]

        return results

    def extract_from_file(self, file_path: str, types: Optional[List[str]] = None) -> Dict:
        """Extract IOCs from file"""
        try:
            # Try to read as text
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            return self.extract_from_text(text, types)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}", file=sys.stderr)
            return {}

    def get_summary(self, results: Dict) -> Dict:
        """Get summary statistics"""
        summary = {
            "total_iocs": 0,
            "ips": len(results.get("ips", [])),
            "domains": len(results.get("domains", [])),
            "urls": len(results.get("urls", [])),
            "emails": len(results.get("emails", [])),
            "cves": len(results.get("cves", [])),
        }

        hash_counts = results.get("hashes", {})
        for hash_type, hashes in hash_counts.items():
            count = len(hashes)
            summary[hash_type] = count
            summary["total_iocs"] += count

        summary["total_iocs"] += (
            summary["ips"]
            + summary["domains"]
            + summary["urls"]
            + summary["emails"]
            + summary["cves"]
        )

        return summary


def format_output_json(results: Dict, metadata: Dict) -> str:
    """Format results as JSON"""
    output = {
        "metadata": metadata,
        "summary": results.get("summary", {}),
        "iocs": {
            "ips": results.get("ips", []),
            "domains": results.get("domains", []),
            "urls": results.get("urls", []),
            "emails": results.get("emails", []),
            "hashes": results.get("hashes", {}),
            "cves": results.get("cves", []),
        },
    }
    return json.dumps(output, indent=2)


def format_output_csv(results: Dict) -> str:
    """Format results as CSV"""
    lines = ["IOC_Type,Value"]

    for ip in results.get("ips", []):
        lines.append(f"ip,{ip}")

    for domain in results.get("domains", []):
        lines.append(f"domain,{domain}")

    for url in results.get("urls", []):
        lines.append(f"url,{url}")

    for email in results.get("emails", []):
        lines.append(f"email,{email}")

    for cve in results.get("cves", []):
        lines.append(f"cve,{cve}")

    hashes = results.get("hashes", {})
    for hash_type, hash_list in hashes.items():
        for h in hash_list:
            lines.append(f"{hash_type},{h}")

    return "\n".join(lines)


def format_output_text(results: Dict) -> str:
    """Format results as plain text"""
    lines = []

    if results.get("ips"):
        lines.append("=== IP Addresses ===")
        lines.extend(results["ips"])
        lines.append("")

    if results.get("domains"):
        lines.append("=== Domains ===")
        lines.extend(results["domains"])
        lines.append("")

    if results.get("urls"):
        lines.append("=== URLs ===")
        lines.extend(results["urls"])
        lines.append("")

    if results.get("emails"):
        lines.append("=== Email Addresses ===")
        lines.extend(results["emails"])
        lines.append("")

    hashes = results.get("hashes", {})
    for hash_type, hash_list in hashes.items():
        if hash_list:
            lines.append(f"=== {hash_type.upper()} Hashes ===")
            lines.extend(hash_list)
            lines.append("")

    if results.get("cves"):
        lines.append("=== CVEs ===")
        lines.extend(results["cves"])
        lines.append("")

    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="IOC Extractor - Extract indicators of compromise from text sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract all IOCs from a file
  python extractor.py report.txt

  # Extract only IPs and domains
  python extractor.py report.txt --types ip,domain

  # Export to CSV
  python extractor.py report.txt --format csv --output iocs.csv

  # Exclude private IPs
  python extractor.py logs.txt --no-private-ips

  # Defang IOCs for safe sharing
  python extractor.py report.txt --defang --output safe_report.txt
        """,
    )

    parser.add_argument("input", nargs="?", help="Input file (use - for stdin)")

    parser.add_argument(
        "--types",
        "-t",
        help="IOC types to extract (comma-separated): ip,domain,url,email,hash,cve,all (default: all)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv", "txt", "stix"],
        default="json",
        help="Output format (default: json)",
    )

    parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    parser.add_argument("--whitelist", "-w", help="Path to whitelist file (domains to exclude)")

    parser.add_argument(
        "--no-private-ips", action="store_true", help="Exclude private IP addresses"
    )

    parser.add_argument(
        "--defang", action="store_true", help="Defang IOCs in output (make safe for sharing)"
    )

    parser.add_argument(
        "--refang", action="store_true", help="Refang defanged IOCs (convert to active form)"
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    args = parse_args()

    # Validate input
    if not args.input or args.input == "-":
        # Read from stdin
        if sys.stdin.isatty():
            print("Error: No input provided. Use a file or pipe input via stdin.", file=sys.stderr)
            sys.exit(1)
        text = sys.stdin.read()
        source = "stdin"
    else:
        if not Path(args.input).exists():
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        source = args.input
        text = None

    # Parse types
    types = None
    if args.types:
        types = [t.strip() for t in args.types.split(",")]

    # Initialize extractor
    extractor = IOCExtractor(
        exclude_private_ips=args.no_private_ips,
        whitelist_file=args.whitelist,
        refang=args.refang,
        defang=args.defang,
    )

    # Extract IOCs
    if args.verbose:
        print(f"Extracting IOCs from {source}...", file=sys.stderr)

    if text is not None:
        results = extractor.extract_from_text(text, types)
    else:
        results = extractor.extract_from_file(source, types)

    # Add summary
    summary = extractor.get_summary(results)
    results["summary"] = summary

    if args.verbose:
        print(f"Found {summary['total_iocs']} total IOCs", file=sys.stderr)

    # Format output
    metadata = {
        "source": source,
        "extraction_date": __import__("datetime").datetime.now().isoformat(),
        "ioc_extractor_version": "1.0.0",
    }

    if args.format == "json":
        output = format_output_json(results, metadata)
    elif args.format == "csv":
        output = format_output_csv(results)
    elif args.format == "txt":
        output = format_output_text(results)
    elif args.format == "stix":
        # Import STIX exporter
        try:
            from vlair.common.stix_export import export_to_stix

            output = export_to_stix(
                ioc_data=results, output_type="simple", description=f"IOCs extracted from {source}"
            )
        except ImportError:
            print(
                "Error: STIX export module not found. Please ensure common/stix_export.py exists.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
