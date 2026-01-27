#!/usr/bin/env python3
"""
Certificate Analyzer - SSL/TLS Certificate Security Analysis

Analyze SSL/TLS certificates for security issues, expiration, chain validation,
phishing detection, and certificate transparency lookups.
"""

import sys
import json
import argparse
import socket
import ssl
import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    print(
        "Error: cryptography library not installed. Install with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import requests
except ImportError:
    print(
        "Error: requests library not installed. Install with: pip install requests", file=sys.stderr
    )
    sys.exit(1)


class CertificateRetriever:
    """Retrieve certificates from various sources"""

    @staticmethod
    def from_https_server(hostname: str, port: int = 443, timeout: int = 10) -> Optional[bytes]:
        """Retrieve certificate from HTTPS server"""
        try:
            context = ssl.create_default_context()
            # Don't verify to allow retrieving invalid certs
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    return der_cert
        except Exception as e:
            print(f"Error retrieving certificate from {hostname}:{port}: {e}", file=sys.stderr)
            return None

    @staticmethod
    def from_file(file_path: str) -> Optional[bytes]:
        """Load certificate from PEM or DER file"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Try PEM first
            if b"-----BEGIN CERTIFICATE-----" in data:
                cert = x509.load_pem_x509_certificate(data, default_backend())
                return cert.public_bytes(serialization.Encoding.DER)
            else:
                # Assume DER
                return data
        except Exception as e:
            print(f"Error loading certificate from {file_path}: {e}", file=sys.stderr)
            return None

    @staticmethod
    def get_cert_chain(hostname: str, port: int = 443) -> List[bytes]:
        """Retrieve full certificate chain"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    chain = ssock.get_peer_cert_chain()
                    if chain:
                        return [cert.public_bytes(serialization.Encoding.DER) for cert in chain]
                    return []
        except Exception:
            return []


class CertificateAnalyzer:
    """Analyze SSL/TLS certificates"""

    # Common brand names for phishing detection
    COMMON_BRANDS = [
        "paypal",
        "apple",
        "microsoft",
        "google",
        "amazon",
        "facebook",
        "instagram",
        "twitter",
        "linkedin",
        "netflix",
        "adobe",
        "ebay",
        "dropbox",
        "outlook",
        "office365",
        "icloud",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "citibank",
        "americanexpress",
    ]

    # Weak signature algorithms
    WEAK_ALGORITHMS = ["md5", "sha1"]

    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse_certificate(self, cert_data: bytes) -> Optional[x509.Certificate]:
        """Parse DER-encoded certificate"""
        try:
            return x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception as e:
            if self.verbose:
                print(f"Error parsing certificate: {e}", file=sys.stderr)
            return None

    def analyze(self, cert_data: bytes, hostname: str = None) -> Dict:
        """Perform comprehensive certificate analysis"""
        cert = self.parse_certificate(cert_data)
        if not cert:
            return {"error": "Failed to parse certificate"}

        result = {
            "analysis_date": datetime.utcnow().isoformat() + "Z",
            "hostname": hostname,
            "certificate": self.extract_certificate_info(cert),
            "validation": self.validate_certificate(cert, hostname),
            "security": self.check_security_issues(cert),
            "phishing": self.check_phishing_indicators(cert, hostname),
            "verdict": "unknown",
            "risk_score": 0,
        }

        # Calculate overall verdict and risk score
        result["verdict"], result["risk_score"] = self.calculate_verdict(result)

        return result

    def extract_certificate_info(self, cert: x509.Certificate) -> Dict:
        """Extract basic certificate information"""
        info = {
            "version": cert.version.name,
            "serial_number": hex(cert.serial_number),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "issuer": self.get_name_attributes(cert.issuer),
            "subject": self.get_name_attributes(cert.subject),
            "validity": {
                "not_before": cert.not_valid_before.isoformat() + "Z",
                "not_after": cert.not_valid_after.isoformat() + "Z",
                "days_remaining": (cert.not_valid_after - datetime.now(timezone.utc)).days,
            },
            "public_key": {
                "algorithm": cert.public_key().__class__.__name__,
                "size": self.get_key_size(cert),
            },
            "extensions": self.extract_extensions(cert),
            "fingerprints": {
                "sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
                "sha1": hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
            },
        }

        return info

    def get_name_attributes(self, name: x509.Name) -> Dict:
        """Extract name attributes"""
        attrs = {}
        for attr in name:
            attrs[attr.oid._name] = attr.value
        return attrs

    def get_key_size(self, cert: x509.Certificate) -> Optional[int]:
        """Get public key size in bits"""
        try:
            public_key = cert.public_key()
            if hasattr(public_key, "key_size"):
                return public_key.key_size
        except Exception:
            pass
        return None

    def extract_extensions(self, cert: x509.Certificate) -> Dict:
        """Extract certificate extensions"""
        extensions = {}

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            extensions["subject_alternative_names"] = list(san_names)
        except x509.ExtensionNotFound:
            extensions["subject_alternative_names"] = []

        # Key Usage
        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = key_usage_ext.value
            extensions["key_usage"] = {
                "digital_signature": (
                    ku.digital_signature if hasattr(ku, "digital_signature") else False
                ),
                "key_encipherment": (
                    ku.key_encipherment if hasattr(ku, "key_encipherment") else False
                ),
                "key_cert_sign": ku.key_cert_sign if hasattr(ku, "key_cert_sign") else False,
            }
        except x509.ExtensionNotFound:
            extensions["key_usage"] = {}

        # Extended Key Usage
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            extensions["extended_key_usage"] = [oid._name for oid in eku_ext.value]
        except x509.ExtensionNotFound:
            extensions["extended_key_usage"] = []

        # Basic Constraints
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            extensions["basic_constraints"] = {
                "ca": bc_ext.value.ca,
                "path_length": bc_ext.value.path_length,
            }
        except x509.ExtensionNotFound:
            extensions["basic_constraints"] = {"ca": False}

        return extensions

    def validate_certificate(self, cert: x509.Certificate, hostname: str = None) -> Dict:
        """Validate certificate"""
        validation = {"is_valid": True, "errors": [], "warnings": []}

        # Check expiration
        now = datetime.now(timezone.utc)
        if cert.not_valid_after < now:
            validation["is_valid"] = False
            validation["errors"].append("Certificate has expired")
        elif cert.not_valid_before > now:
            validation["is_valid"] = False
            validation["errors"].append("Certificate is not yet valid")

        # Check if expiring soon (30 days)
        days_remaining = (cert.not_valid_after - now).days
        if 0 < days_remaining < 30:
            validation["warnings"].append(f"Certificate expiring soon ({days_remaining} days)")

        # Check self-signed
        if cert.issuer == cert.subject:
            validation["warnings"].append("Certificate is self-signed")

        # Check hostname match if provided
        if hostname:
            if not self.check_hostname_match(cert, hostname):
                validation["errors"].append(f"Hostname {hostname} does not match certificate")
                validation["is_valid"] = False

        return validation

    def check_hostname_match(self, cert: x509.Certificate, hostname: str) -> bool:
        """Check if hostname matches certificate CN or SAN"""
        # Check CN
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if self.match_hostname(cn, hostname):
                return True
        except Exception:
            pass

        # Check SAN
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            for san_name in san_names:
                if self.match_hostname(san_name, hostname):
                    return True
        except x509.ExtensionNotFound:
            pass

        return False

    def match_hostname(self, pattern: str, hostname: str) -> bool:
        """Match hostname against certificate name (supports wildcards)"""
        pattern = pattern.lower()
        hostname = hostname.lower()

        if pattern == hostname:
            return True

        # Wildcard matching
        if pattern.startswith("*."):
            pattern_parts = pattern[2:].split(".")
            hostname_parts = hostname.split(".")[1:]  # Skip first part
            return pattern_parts == hostname_parts

        return False

    def check_security_issues(self, cert: x509.Certificate) -> Dict:
        """Check for security issues"""
        issues = {"critical": [], "high": [], "medium": [], "low": []}

        # Check signature algorithm
        sig_alg = cert.signature_algorithm_oid._name.lower()
        for weak_alg in self.WEAK_ALGORITHMS:
            if weak_alg in sig_alg:
                issues["high"].append(f"Weak signature algorithm: {sig_alg}")

        # Check key size
        key_size = self.get_key_size(cert)
        if key_size:
            if key_size < 2048:
                issues["high"].append(f"Weak key size: {key_size} bits (should be >= 2048)")
            elif key_size < 3072:
                issues["medium"].append(f"Key size {key_size} bits is adequate but not recommended")

        # Check validity period (> 398 days is suspicious as of 2020)
        validity_days = (cert.not_valid_after - cert.not_valid_before).days
        if validity_days > 398:
            issues["low"].append(
                f"Long validity period: {validity_days} days (max recommended: 398)"
            )

        return issues

    def check_phishing_indicators(self, cert: x509.Certificate, hostname: str = None) -> Dict:
        """Check for phishing indicators"""
        indicators = {"suspicious": [], "confidence": 0}

        # Get certificate subject CN
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower()
        except Exception:
            cn = ""

        # Get all SAN names
        san_names = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = [name.lower() for name in san_ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            pass

        all_names = [cn] + san_names

        # Check for brand impersonation
        for name in all_names:
            for brand in self.COMMON_BRANDS:
                if brand in name and brand not in hostname if hostname else True:
                    indicators["suspicious"].append(
                        f'Possible brand impersonation: {name} contains "{brand}"'
                    )
                    indicators["confidence"] += 20

        # Check for suspicious patterns
        suspicious_patterns = [
            r"(verify|secure|update|confirm|account|login|signin)",
            r"\d{4,}",  # Long numbers
            r"[a-z]{20,}",  # Very long strings
        ]

        for name in all_names:
            for pattern in suspicious_patterns:
                if re.search(pattern, name):
                    indicators["suspicious"].append(f"Suspicious pattern in: {name}")
                    indicators["confidence"] += 10
                    break

        # Check for very new certificates (< 7 days)
        cert_age_days = (datetime.now(timezone.utc) - cert.not_valid_before).days
        if cert_age_days < 7:
            indicators["suspicious"].append(f"Very new certificate (age: {cert_age_days} days)")
            indicators["confidence"] += 15

        # Cap confidence at 100
        indicators["confidence"] = min(indicators["confidence"], 100)

        return indicators

    def calculate_verdict(self, analysis: Dict) -> Tuple[str, int]:
        """Calculate overall verdict and risk score"""
        risk_score = 0

        # Validation errors
        if not analysis["validation"]["is_valid"]:
            risk_score += 40

        # Security issues
        security = analysis["security"]
        risk_score += len(security["critical"]) * 25
        risk_score += len(security["high"]) * 15
        risk_score += len(security["medium"]) * 5
        risk_score += len(security["low"]) * 2

        # Phishing indicators
        risk_score += min(analysis["phishing"]["confidence"], 40)

        # Cap at 100
        risk_score = min(risk_score, 100)

        # Determine verdict
        if risk_score >= 70:
            verdict = "high_risk"
        elif risk_score >= 40:
            verdict = "medium_risk"
        elif risk_score > 0:
            verdict = "low_risk"
        else:
            verdict = "trusted"

        return verdict, risk_score


class CertificateTransparency:
    """Query Certificate Transparency logs"""

    @staticmethod
    def query_crtsh(domain: str) -> List[Dict]:
        """Query crt.sh for certificates"""
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                return data
        except Exception as e:
            print(f"Error querying crt.sh: {e}", file=sys.stderr)

        return []


def format_output_json(result: Dict) -> str:
    """Format output as JSON"""
    return json.dumps(result, indent=2)


def format_output_text(result: Dict) -> str:
    """Format output as human-readable text"""
    lines = []
    lines.append("=" * 80)
    lines.append("Certificate Analysis Report")
    lines.append("=" * 80)
    lines.append("")

    if "error" in result:
        lines.append(f"ERROR: {result['error']}")
        return "\n".join(lines)

    # Summary
    lines.append(f"Hostname: {result.get('hostname', 'N/A')}")
    lines.append(f"Verdict: {result['verdict'].upper().replace('_', ' ')}")
    lines.append(f"Risk Score: {result['risk_score']}/100")
    lines.append("")

    # Certificate Info
    cert = result["certificate"]
    lines.append("Certificate Information:")
    lines.append(f"  Subject: {cert['subject'].get('commonName', 'N/A')}")
    lines.append(f"  Issuer: {cert['issuer'].get('commonName', 'N/A')}")
    lines.append(f"  Valid From: {cert['validity']['not_before']}")
    lines.append(f"  Valid Until: {cert['validity']['not_after']}")
    lines.append(f"  Days Remaining: {cert['validity']['days_remaining']}")
    lines.append(f"  Serial Number: {cert['serial_number']}")
    lines.append(f"  Signature Algorithm: {cert['signature_algorithm']}")
    lines.append(
        f"  Public Key: {cert['public_key']['algorithm']} ({cert['public_key']['size']} bits)"
    )
    lines.append("")

    # SANs
    if cert["extensions"]["subject_alternative_names"]:
        lines.append("Subject Alternative Names:")
        for san in cert["extensions"]["subject_alternative_names"][:10]:  # Limit to 10
            lines.append(f"  - {san}")
        lines.append("")

    # Validation
    validation = result["validation"]
    lines.append("Validation Status:")
    lines.append(f"  Valid: {'YES' if validation['is_valid'] else 'NO'}")
    if validation["errors"]:
        lines.append("  Errors:")
        for error in validation["errors"]:
            lines.append(f"    - {error}")
    if validation["warnings"]:
        lines.append("  Warnings:")
        for warning in validation["warnings"]:
            lines.append(f"    - {warning}")
    lines.append("")

    # Security Issues
    security = result["security"]
    has_issues = any(security[level] for level in ["critical", "high", "medium", "low"])
    if has_issues:
        lines.append("Security Issues:")
        for level in ["critical", "high", "medium", "low"]:
            if security[level]:
                lines.append(f"  {level.upper()}:")
                for issue in security[level]:
                    lines.append(f"    - {issue}")
        lines.append("")

    # Phishing Indicators
    phishing = result["phishing"]
    if phishing["suspicious"]:
        lines.append(f"Phishing Indicators (Confidence: {phishing['confidence']}%):")
        for indicator in phishing["suspicious"]:
            lines.append(f"  - {indicator}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Certificate Analyzer - SSL/TLS Certificate Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze HTTPS server certificate
  python analyzer.py https://example.com

  # Analyze certificate file
  python analyzer.py --file cert.pem

  # Specify hostname for validation
  python analyzer.py --file cert.pem --hostname example.com

  # Output to JSON file
  python analyzer.py https://example.com --format json --output cert.json

  # Query Certificate Transparency logs
  python analyzer.py --ct-search example.com

  # Batch analysis from file
  python analyzer.py --file-list domains.txt --format json
        """,
    )

    parser.add_argument("target", nargs="?", help="HTTPS URL or hostname to analyze")
    parser.add_argument("--file", "-f", help="Certificate file (PEM or DER)")
    parser.add_argument("--file-list", help="File containing list of domains (one per line)")
    parser.add_argument("--hostname", help="Hostname for validation (when using --file)")
    parser.add_argument("--port", type=int, default=443, help="Port number (default: 443)")
    parser.add_argument("--ct-search", help="Search Certificate Transparency logs for domain")
    parser.add_argument(
        "--format",
        "-fmt",
        choices=["json", "txt"],
        default="txt",
        help="Output format (default: txt)",
    )
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    analyzer = CertificateAnalyzer(verbose=args.verbose)
    retriever = CertificateRetriever()

    results = []

    # Certificate Transparency search
    if args.ct_search:
        if args.verbose:
            print(
                f"Querying Certificate Transparency logs for {args.ct_search}...", file=sys.stderr
            )

        ct = CertificateTransparency()
        ct_results = ct.query_crtsh(args.ct_search)

        output = {
            "domain": args.ct_search,
            "certificates_found": len(ct_results),
            "certificates": ct_results[:50],  # Limit to 50
        }

        if args.format == "json":
            print(json.dumps(output, indent=2))
        else:
            print(f"Found {len(ct_results)} certificates for {args.ct_search}")
            for i, cert in enumerate(ct_results[:10], 1):  # Show first 10
                print(f"\n{i}. Issuer: {cert.get('issuer_name', 'N/A')}")
                print(f"   Not Before: {cert.get('not_before', 'N/A')}")
                print(f"   Not After: {cert.get('not_after', 'N/A')}")

        sys.exit(0)

    # Batch processing
    if args.file_list:
        with open(args.file_list, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

        if args.verbose:
            print(f"Analyzing {len(domains)} domains...", file=sys.stderr)

        for domain in domains:
            # Remove protocol if present
            if "://" in domain:
                domain = urlparse(domain).netloc

            if args.verbose:
                print(f"Analyzing {domain}...", file=sys.stderr)

            cert_data = retriever.from_https_server(domain, args.port)
            if cert_data:
                result = analyzer.analyze(cert_data, domain)
                results.append(result)

        # Output batch results
        if args.format == "json":
            output = {
                "metadata": {
                    "tool": "certificate_analyzer",
                    "version": "1.0.0",
                    "analysis_date": datetime.utcnow().isoformat() + "Z",
                    "total_analyzed": len(results),
                },
                "results": results,
            }
            output_str = json.dumps(output, indent=2)
        else:
            output_str = "\n\n".join([format_output_text(r) for r in results])

        if args.output:
            with open(args.output, "w") as f:
                f.write(output_str)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(output_str)

        sys.exit(0)

    # Single certificate analysis
    cert_data = None
    hostname = args.hostname

    if args.file:
        # Load from file
        cert_data = retriever.from_file(args.file)
    elif args.target:
        # Fetch from server
        # Parse URL if provided
        if "://" in args.target:
            parsed = urlparse(args.target)
            hostname = parsed.netloc
        else:
            hostname = args.target

        cert_data = retriever.from_https_server(hostname, args.port)
    else:
        print("Error: No target specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    if not cert_data:
        print("Error: Failed to retrieve certificate", file=sys.stderr)
        sys.exit(1)

    # Analyze certificate
    result = analyzer.analyze(cert_data, hostname)

    # Format output
    if args.format == "json":
        output = format_output_json(result)
    else:
        output = format_output_text(result)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    sys.exit(0)


if __name__ == "__main__":
    main()
