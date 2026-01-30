#!/usr/bin/env python3
"""
Domain/IP Intelligence - Comprehensive threat intelligence for domains and IPs
Supports WHOIS, DNS, GeoIP, and threat intelligence lookups with Redis caching
"""

import sys
import json
import argparse
import os
import socket
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv
import re

# Import unified cache manager
from vlair.common.cache_manager import get_cache

load_dotenv()


class Validator:
    """Validate IP addresses and domains"""

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Check if valid IPv4"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if valid domain format"""
        if len(domain) > 253:
            return False
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False

        first_octet = int(parts[0])
        second_octet = int(parts[1])

        # 10.0.0.0/8
        if first_octet == 10:
            return True
        # 172.16.0.0/12
        if first_octet == 172 and 16 <= second_octet <= 31:
            return True
        # 192.168.0.0/16
        if first_octet == 192 and second_octet == 168:
            return True
        # Loopback and link-local
        if first_octet == 127 or first_octet == 169:
            return True

        return False


class DNSLookup:
    """DNS resolution and analysis"""

    @staticmethod
    def resolve_a(domain: str) -> List[str]:
        """Resolve A records"""
        try:
            return socket.gethostbyname_ex(domain)[2]
        except Exception:
            return []

    @staticmethod
    def resolve_ptr(ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    @staticmethod
    def get_dns_info(domain: str) -> Dict:
        """Get comprehensive DNS information"""
        info = {
            "a_records": [],
            "reverse_dns": {},
        }

        # Get A records
        a_records = DNSLookup.resolve_a(domain)
        info["a_records"] = a_records

        # Get reverse DNS for each IP
        for ip in a_records:
            ptr = DNSLookup.resolve_ptr(ip)
            if ptr:
                info["reverse_dns"][ip] = ptr

        return info


class AbuseIPDBAPI:
    """AbuseIPDB API integration"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP on AbuseIPDB"""
        if not self.api_key:
            return None

        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

            response = requests.get(
                f"{self.BASE_URL}/check", headers=headers, params=params, timeout=15
            )

            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "source": "abuseipdb",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "permalink": f"https://www.abuseipdb.com/check/{ip}",
                }

        except Exception as e:
            return {"source": "abuseipdb", "error": str(e)}

        return None


class VirusTotalAPI:
    """VirusTotal API for domain/IP lookups"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP on VirusTotal"""
        if not self.api_key:
            return None

        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip}", headers=headers, timeout=15
            )

            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})

                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "as_owner": data.get("as_owner"),
                    "country": data.get("country"),
                    "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
                }

        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

        return None

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        """Lookup domain on VirusTotal"""
        if not self.api_key:
            return None

        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.base_url}/domains/{domain}", headers=headers, timeout=15
            )

            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})

                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "categories": data.get("categories", {}),
                    "creation_date": data.get("creation_date"),
                    "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
                }

        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

        return None


class RiskScorer:
    """Calculate risk scores for IPs and domains"""

    @staticmethod
    def calculate_ip_score(intel_data: Dict) -> int:
        """Calculate IP risk score (0-100)"""
        score = 0

        # AbuseIPDB scoring
        abuseipdb = intel_data.get("threat_intelligence", {}).get("abuseipdb", {})
        if abuseipdb:
            abuse_score = abuseipdb.get("abuse_confidence_score", 0)
            score += abuse_score * 0.5  # 50% weight

        # VirusTotal scoring
        vt = intel_data.get("threat_intelligence", {}).get("virustotal", {})
        if vt:
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                score += min(malicious * 5, 40)  # Max 40 points

        return min(int(score), 100)

    @staticmethod
    def calculate_domain_score(intel_data: Dict) -> int:
        """Calculate domain risk score (0-100)"""
        score = 0

        # VirusTotal scoring
        vt = intel_data.get("threat_intelligence", {}).get("virustotal", {})
        if vt:
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            score += min(malicious * 5, 50)
            score += min(suspicious * 2, 20)

        return min(int(score), 100)

    @staticmethod
    def classify_risk(score: int) -> str:
        """Classify risk level"""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Clean"


class DomainIPIntelligence:
    """Main intelligence orchestrator"""

    CACHE_NAMESPACE = "domain_ip_intel"
    CACHE_TTL = 86400  # 24 hours

    def __init__(self, verbose=False, cache_enabled=True):
        self.verbose = verbose
        self.cache = get_cache() if cache_enabled else None

        # Initialize APIs
        vt_key = os.getenv("VT_API_KEY")
        abuseipdb_key = os.getenv("ABUSEIPDB_KEY")

        self.vt_api = VirusTotalAPI(vt_key) if vt_key else None
        self.abuseipdb_api = AbuseIPDBAPI(abuseipdb_key) if abuseipdb_key else None

    def analyze_ip(self, ip: str) -> Dict:
        """Comprehensive IP analysis"""
        if not Validator.is_valid_ipv4(ip):
            return {"target": ip, "type": "invalid", "error": "Invalid IP address format"}

        # Check cache
        if self.cache:
            cached = self.cache.get(f"ip:{ip}", namespace=self.CACHE_NAMESPACE)
            if cached:
                if self.verbose:
                    print(f"[Cache hit] {ip}", file=sys.stderr)
                cached["cached"] = True
                return cached

        if self.verbose:
            print(f"[Analyzing IP] {ip}", file=sys.stderr)

        result = {
            "target": ip,
            "type": "ipv4",
            "lookup_date": datetime.now().isoformat(),
            "is_private": Validator.is_private_ip(ip),
            "cached": False,
        }

        # Skip threat intel for private IPs
        if result["is_private"]:
            result["note"] = "Private IP address - skipping threat intelligence lookups"
            # Still cache private IP results (quick lookups)
            if self.cache:
                self.cache.set(
                    f"ip:{ip}", result, namespace=self.CACHE_NAMESPACE, ttl=self.CACHE_TTL
                )
            return result

        # Reverse DNS
        result["reverse_dns"] = DNSLookup.resolve_ptr(ip)

        # Threat Intelligence
        result["threat_intelligence"] = {}

        if self.abuseipdb_api:
            abuseipdb_result = self.abuseipdb_api.lookup_ip(ip)
            if abuseipdb_result:
                result["threat_intelligence"]["abuseipdb"] = abuseipdb_result

        if self.vt_api:
            vt_result = self.vt_api.lookup_ip(ip)
            if vt_result:
                result["threat_intelligence"]["virustotal"] = vt_result

        # Calculate risk score
        score = RiskScorer.calculate_ip_score(result)
        result["reputation"] = {"score": score, "risk_level": RiskScorer.classify_risk(score)}

        # Cache result
        if self.cache:
            self.cache.set(f"ip:{ip}", result, namespace=self.CACHE_NAMESPACE, ttl=self.CACHE_TTL)

        return result

    def analyze_domain(self, domain: str) -> Dict:
        """Comprehensive domain analysis"""
        domain = domain.lower().strip()

        if not Validator.is_valid_domain(domain):
            return {"target": domain, "type": "invalid", "error": "Invalid domain format"}

        # Check cache
        if self.cache:
            cached = self.cache.get(f"domain:{domain}", namespace=self.CACHE_NAMESPACE)
            if cached:
                if self.verbose:
                    print(f"[Cache hit] {domain}", file=sys.stderr)
                cached["cached"] = True
                return cached

        if self.verbose:
            print(f"[Analyzing Domain] {domain}", file=sys.stderr)

        result = {
            "target": domain,
            "type": "domain",
            "lookup_date": datetime.now().isoformat(),
            "cached": False,
        }

        # DNS Information
        result["dns"] = DNSLookup.get_dns_info(domain)

        # Threat Intelligence
        result["threat_intelligence"] = {}

        if self.vt_api:
            vt_result = self.vt_api.lookup_domain(domain)
            if vt_result:
                result["threat_intelligence"]["virustotal"] = vt_result

        # Calculate risk score
        score = RiskScorer.calculate_domain_score(result)
        result["reputation"] = {"score": score, "risk_level": RiskScorer.classify_risk(score)}

        # Cache result
        if self.cache:
            self.cache.set(
                f"domain:{domain}", result, namespace=self.CACHE_NAMESPACE, ttl=self.CACHE_TTL
            )

        return result

    def analyze(self, target: str) -> Dict:
        """Auto-detect type and analyze"""
        if Validator.is_valid_ipv4(target):
            return self.analyze_ip(target)
        elif Validator.is_valid_domain(target):
            return self.analyze_domain(target)
        else:
            return {
                "target": target,
                "type": "unknown",
                "error": "Could not determine if target is IP or domain",
            }


def format_output_json(results: List[Dict], metadata: Dict) -> str:
    """Format results as JSON"""
    output = {"metadata": metadata, "results": results}
    return json.dumps(output, indent=2)


def format_output_csv(results: List[Dict]) -> str:
    """Format results as CSV"""
    lines = ["Target,Type,Risk_Level,Risk_Score,Reverse_DNS,AbuseIPDB_Score,VT_Malicious,VT_Link"]

    for r in results:
        target = r.get("target", "")
        target_type = r.get("type", "")
        risk = r.get("reputation", {})
        risk_level = risk.get("risk_level", "N/A")
        risk_score = risk.get("score", 0)

        reverse_dns = r.get("reverse_dns", "")

        threat_intel = r.get("threat_intelligence", {})
        abuseipdb = threat_intel.get("abuseipdb", {})
        abuseipdb_score = abuseipdb.get("abuse_confidence_score", 0)

        vt = threat_intel.get("virustotal", {})
        vt_malicious = vt.get("malicious", 0)
        vt_link = vt.get("permalink", "")

        lines.append(
            f"{target},{target_type},{risk_level},{risk_score},{reverse_dns},{abuseipdb_score},{vt_malicious},{vt_link}"
        )

    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Domain/IP Intelligence - Comprehensive threat intelligence lookup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze IP address
  python intel.py 8.8.8.8

  # Analyze domain
  python intel.py example.com

  # Batch analysis from file
  python intel.py --file targets.txt --format csv --output results.csv
        """,
    )

    parser.add_argument("target", nargs="?", help="IP address or domain name")

    parser.add_argument("--file", "-f", help="File with targets (one per line)")

    parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    parser.add_argument(
        "--format", choices=["json", "csv"], default="json", help="Output format (default: json)"
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    args = parse_args()

    # Collect targets
    targets = []

    if args.target:
        targets.append(args.target)

    if args.file:
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        with open(args.file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if not targets:
        print("Error: No targets provided. Use argument or --file", file=sys.stderr)
        sys.exit(1)

    # Check for API keys
    if not os.getenv("VT_API_KEY"):
        print("Warning: VT_API_KEY not set. VirusTotal lookups will be skipped.", file=sys.stderr)
    if not os.getenv("ABUSEIPDB_KEY"):
        print("Warning: ABUSEIPDB_KEY not set. AbuseIPDB lookups will be skipped.", file=sys.stderr)

    # Initialize intelligence
    intel = DomainIPIntelligence(verbose=args.verbose)

    # Perform analysis
    results = []
    for target in targets:
        result = intel.analyze(target)
        results.append(result)

    # Format output
    metadata = {"analysis_date": datetime.now().isoformat(), "total_targets": len(results)}

    if args.format == "json":
        output = format_output_json(results, metadata)
    elif args.format == "csv":
        output = format_output_csv(results)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"\nOutput written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
