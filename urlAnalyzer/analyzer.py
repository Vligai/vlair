#!/usr/bin/env python3
"""
URL Analyzer - Comprehensive URL threat analysis
Supports VirusTotal, URLhaus, and pattern-based detection
"""

import sys
import json
import argparse
import os
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv

# Import unified cache manager
sys.path.insert(0, str(Path(__file__).parent.parent))
from common.cache_manager import get_cache

load_dotenv()


class URLValidator:
    """Validate and normalize URLs"""

    URL_PATTERN = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IP
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid"""
        return bool(URLValidator.URL_PATTERN.match(url))

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL (add scheme if missing, lowercase domain)"""
        url = url.strip()

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Parse and reconstruct
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"

        if parsed.params:
            normalized += f";{parsed.params}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"

        return normalized

    @staticmethod
    def defang_url(url: str) -> str:
        """Defang URL for safe sharing"""
        url = url.replace("http://", "hxxp://")
        url = url.replace("https://", "hxxps://")
        url = url.replace(".", "[.]")
        return url


class URLParser:
    """Parse and decompose URLs"""

    @staticmethod
    def parse_url(url: str) -> Dict:
        """Parse URL into components"""
        parsed = urlparse(url)

        result = {
            "original": url,
            "scheme": parsed.scheme,
            "domain": parsed.netloc.lower(),
            "port": parsed.port,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "query_params": {},
        }

        # Parse query parameters
        if parsed.query:
            result["query_params"] = {k: v for k, v in parse_qs(parsed.query).items()}

        # Extract file extension from path
        if parsed.path:
            path_parts = parsed.path.split("/")
            if path_parts[-1] and "." in path_parts[-1]:
                result["file_extension"] = path_parts[-1].split(".")[-1].lower()
            else:
                result["file_extension"] = None
        else:
            result["file_extension"] = None

        # Get base domain
        domain_parts = parsed.netloc.split(".")
        if len(domain_parts) >= 2:
            result["base_domain"] = ".".join(domain_parts[-2:])
        else:
            result["base_domain"] = parsed.netloc

        return result


class SuspiciousPatternDetector:
    """Detect suspicious patterns in URLs"""

    SUSPICIOUS_KEYWORDS = [
        "login",
        "signin",
        "account",
        "verify",
        "secure",
        "update",
        "confirm",
        "banking",
        "paypal",
        "apple",
        "microsoft",
        "amazon",
        "suspended",
        "locked",
        "unusual",
        "activity",
        "alert",
    ]

    SUSPICIOUS_EXTENSIONS = ["exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar", "apk", "dex", "zip", "rar", "7z"]

    SUSPICIOUS_PATTERNS = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address in URL
        r"[a-z0-9]{20,}",  # Long random strings
        r"%[0-9a-f]{2}",  # URL encoding (potential obfuscation)
        r"\.tk$|\.ml$|\.ga$|\.cf$|\.gq$",  # Free TLD domains
    ]

    @staticmethod
    def analyze_url(url: str, parsed: Dict) -> Dict:
        """Analyze URL for suspicious patterns"""
        suspicions = []
        risk_score = 0

        # Check for IP address instead of domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed["domain"]):
            suspicions.append("Uses IP address instead of domain name")
            risk_score += 20

        # Check for suspicious keywords
        url_lower = url.lower()
        found_keywords = [kw for kw in SuspiciousPatternDetector.SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            suspicions.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
            risk_score += len(found_keywords) * 5

        # Check for suspicious file extension
        if parsed.get("file_extension") in SuspiciousPatternDetector.SUSPICIOUS_EXTENSIONS:
            suspicions.append(f"Suspicious file extension: .{parsed['file_extension']}")
            risk_score += 15

        # Check for URL encoding (potential obfuscation)
        if "%" in url:
            encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
            if encoded_count > 3:
                suspicions.append(f"High URL encoding ({encoded_count} encoded chars)")
                risk_score += 10

        # Check for free/suspicious TLDs
        for pattern in [r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"\.gq$"]:
            if re.search(pattern, parsed["domain"]):
                suspicions.append("Uses free/suspicious TLD")
                risk_score += 15
                break

        # Check for excessive subdomain levels
        subdomain_count = parsed["domain"].count(".")
        if subdomain_count > 3:
            suspicions.append(f"Excessive subdomains ({subdomain_count} levels)")
            risk_score += 10

        # Check for long domain
        if len(parsed["domain"]) > 50:
            suspicions.append(f"Unusually long domain ({len(parsed['domain'])} chars)")
            risk_score += 10

        # Check for homograph attack (mixed character sets - basic check)
        if any(ord(c) > 127 for c in url):
            suspicions.append("Contains non-ASCII characters (potential homograph attack)")
            risk_score += 20

        return {"suspicions": suspicions, "risk_score": min(risk_score, 100), "is_suspicious": risk_score > 30}


class VirusTotalURLAPI:
    """VirusTotal URL analysis API"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def analyze_url(self, url: str) -> Optional[Dict]:
        """Analyze URL with VirusTotal"""
        if not self.api_key:
            return None

        try:
            # Submit URL for scanning
            import base64

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_votes": sum(stats.values()),
                    "verdict": self._classify_verdict(stats),
                    "categories": attrs.get("categories", {}),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                }
            elif response.status_code == 404:
                # URL not in database, submit for scanning
                return {"source": "virustotal", "verdict": "unknown", "note": "URL not found in VirusTotal database"}
            else:
                return {"source": "virustotal", "verdict": "error", "error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"source": "virustotal", "verdict": "error", "error": str(e)}

    def _classify_verdict(self, stats: Dict) -> str:
        """Classify verdict from VT stats"""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            return "malicious"
        elif malicious >= 1 or suspicious >= 2:
            return "suspicious"
        elif stats.get("harmless", 0) > 0:
            return "clean"
        else:
            return "unknown"


class URLhausAPI:
    """URLhaus (abuse.ch) API integration"""

    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    def lookup_url(self, url: str) -> Optional[Dict]:
        """Look up URL in URLhaus database"""
        try:
            response = requests.post(f"{self.base_url}/url/", data={"url": url}, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data["query_status"] == "ok":
                    return {
                        "source": "urlhaus",
                        "verdict": "malicious",
                        "threat": data.get("threat"),
                        "tags": data.get("tags", []),
                        "date_added": data.get("date_added"),
                        "url_status": data.get("url_status"),
                        "reporter": data.get("reporter"),
                        "permalink": data.get("urlhaus_reference"),
                    }
                elif data["query_status"] == "no_results":
                    return {"source": "urlhaus", "verdict": "unknown", "note": "URL not found in URLhaus database"}

        except Exception as e:
            return {"source": "urlhaus", "verdict": "error", "error": str(e)}

        return None


class URLAnalyzer:
    """Main URL analyzer orchestrator"""

    CACHE_NAMESPACE = "url_analysis"
    CACHE_TTL = 86400  # 24 hours

    def __init__(self, cache_enabled=True, verbose=False):
        self.cache = get_cache() if cache_enabled else None
        self.verbose = verbose

        # Initialize APIs
        vt_key = os.getenv("VT_API_KEY")
        self.vt_api = VirusTotalURLAPI(vt_key) if vt_key else None
        self.urlhaus_api = URLhausAPI()

    def analyze(self, url: str) -> Dict:
        """Comprehensive URL analysis"""

        # Normalize URL
        try:
            normalized_url = URLValidator.normalize_url(url)
        except:
            return {"url": url, "error": "Invalid URL format"}

        # Validate
        if not URLValidator.is_valid_url(normalized_url):
            return {"url": url, "error": "Invalid URL format"}

        # Check cache
        if self.cache:
            cached = self.cache.get(normalized_url, namespace=self.CACHE_NAMESPACE)
            if cached:
                if self.verbose:
                    print(f"[Cache hit] {normalized_url}", file=sys.stderr)
                cached["cached"] = True
                return cached

        if self.verbose:
            print(f"[Analyzing] {normalized_url}", file=sys.stderr)

        # Parse URL
        parsed = URLParser.parse_url(normalized_url)

        # Detect suspicious patterns
        pattern_analysis = SuspiciousPatternDetector.analyze_url(normalized_url, parsed)

        result = {
            "url": normalized_url,
            "original_url": url,
            "analysis_date": datetime.utcnow().isoformat() + "Z",
            "parsed": parsed,
            "pattern_analysis": pattern_analysis,
            "threat_intelligence": {},
            "cached": False,
        }

        # Query URLhaus
        urlhaus_result = self.urlhaus_api.lookup_url(normalized_url)
        if urlhaus_result:
            result["threat_intelligence"]["urlhaus"] = urlhaus_result

        # Query VirusTotal
        if self.vt_api:
            vt_result = self.vt_api.analyze_url(normalized_url)
            if vt_result:
                result["threat_intelligence"]["virustotal"] = vt_result

        # Calculate overall verdict
        result["verdict"] = self._calculate_verdict(result)
        result["risk_level"] = self._classify_risk(result)

        # Cache result
        if self.cache:
            self.cache.set(normalized_url, result, namespace=self.CACHE_NAMESPACE, ttl=self.CACHE_TTL)

        return result

    def _calculate_verdict(self, result: Dict) -> str:
        """Calculate overall verdict from all sources"""
        ti = result.get("threat_intelligence", {})

        # Check URLhaus first (high confidence)
        if ti.get("urlhaus", {}).get("verdict") == "malicious":
            return "malicious"

        # Check VirusTotal
        vt_verdict = ti.get("virustotal", {}).get("verdict")
        if vt_verdict == "malicious":
            return "malicious"
        elif vt_verdict == "suspicious":
            return "suspicious"

        # Check pattern analysis
        if result.get("pattern_analysis", {}).get("is_suspicious"):
            return "suspicious"

        # If VT says clean and no other issues
        if vt_verdict == "clean":
            return "clean"

        return "unknown"

    def _classify_risk(self, result: Dict) -> str:
        """Classify risk level"""
        verdict = result.get("verdict", "unknown")
        pattern_score = result.get("pattern_analysis", {}).get("risk_score", 0)

        if verdict == "malicious":
            return "high"
        elif verdict == "suspicious" or pattern_score > 50:
            return "medium"
        elif verdict == "clean":
            return "low"
        else:
            return "unknown"

    def analyze_batch(self, urls: List[str]) -> List[Dict]:
        """Analyze multiple URLs"""
        results = []
        total = len(urls)

        for i, url in enumerate(urls, 1):
            if self.verbose:
                print(f"[{i}/{total}] Analyzing {url[:50]}...", file=sys.stderr)

            result = self.analyze(url)
            results.append(result)

        return results


def format_output_json(results: List[Dict], metadata: Dict) -> str:
    """Format results as JSON"""
    output = {"metadata": metadata, "results": results}
    return json.dumps(output, indent=2)


def format_output_csv(results: List[Dict]) -> str:
    """Format results as CSV"""
    lines = ["URL,Verdict,Risk Level,VT Malicious,URLhaus Status,Suspicions"]

    for r in results:
        url = r.get("url", "")
        verdict = r.get("verdict", "unknown")
        risk = r.get("risk_level", "unknown")

        vt_mal = r.get("threat_intelligence", {}).get("virustotal", {}).get("malicious", 0)
        urlhaus = r.get("threat_intelligence", {}).get("urlhaus", {}).get("verdict", "unknown")
        suspicions = len(r.get("pattern_analysis", {}).get("suspicions", []))

        lines.append(f'"{url}",{verdict},{risk},{vt_mal},{urlhaus},{suspicions}')

    return "\n".join(lines)


def format_output_text(results: List[Dict]) -> str:
    """Format results as human-readable text"""
    lines = []

    for r in results:
        lines.append("=" * 80)
        lines.append(f"URL: {r.get('url', 'N/A')}")
        lines.append(f"Verdict: {r.get('verdict', 'unknown').upper()}")
        lines.append(f"Risk Level: {r.get('risk_level', 'unknown').upper()}")

        # Pattern analysis
        pattern = r.get("pattern_analysis", {})
        if pattern.get("suspicions"):
            lines.append(f"\nSuspicious Patterns ({pattern.get('risk_score', 0)}/100):")
            for susp in pattern["suspicions"]:
                lines.append(f"  - {susp}")

        # Threat intelligence
        ti = r.get("threat_intelligence", {})

        if "virustotal" in ti:
            vt = ti["virustotal"]
            if vt.get("verdict") != "error":
                lines.append(f"\nVirusTotal:")
                lines.append(f"  Malicious: {vt.get('malicious', 0)}")
                lines.append(f"  Suspicious: {vt.get('suspicious', 0)}")
                lines.append(f"  Verdict: {vt.get('verdict', 'unknown')}")

        if "urlhaus" in ti:
            uh = ti["urlhaus"]
            if uh.get("verdict") == "malicious":
                lines.append(f"\nURLhaus: MALICIOUS")
                lines.append(f"  Threat: {uh.get('threat', 'N/A')}")
                lines.append(f"  Tags: {', '.join(uh.get('tags', []))}")

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="URL Analyzer - Comprehensive URL threat analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single URL
  python analyzer.py "http://suspicious-site.com"

  # Analyze from file
  python analyzer.py --file urls.txt

  # With output file
  python analyzer.py "http://example.com" --output results.json

  # CSV format
  python analyzer.py --file urls.txt --format csv --output results.csv

  # Verbose mode
  python analyzer.py "http://test.com" --verbose
        """,
    )

    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--file", "-f", help="File containing URLs (one per line)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Output format (default: json)")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    args = parse_args()

    # Get URLs to analyze
    urls = []

    if args.url:
        urls.append(args.url)

    if args.file:
        try:
            with open(args.file, "r") as f:
                file_urls = [line.strip() for line in f if line.strip()]
                urls.extend(file_urls)
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print("Error: No URLs provided. Use positional argument or --file", file=sys.stderr)
        sys.exit(1)

    # Analyze URLs
    analyzer = URLAnalyzer(cache_enabled=not args.no_cache, verbose=args.verbose)
    results = analyzer.analyze_batch(urls)

    # Format output
    metadata = {
        "analysis_date": datetime.utcnow().isoformat() + "Z",
        "total_urls": len(results),
        "tool": "url_analyzer",
        "version": "1.0.0",
    }

    if args.format == "json":
        output = format_output_json(results, metadata)
    elif args.format == "csv":
        output = format_output_csv(results)
    else:  # txt
        output = format_output_text(results)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
