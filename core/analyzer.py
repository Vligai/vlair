#!/usr/bin/env python3
"""
Analyzer - Main orchestration engine for SecOps Helper
Auto-detects input type and runs appropriate analysis tools
Part of SecOps Helper Operationalization (Phase 5)
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.detector import InputDetector, InputType
from core.scorer import RiskScorer, Severity
from core.reporter import Reporter


class Analyzer:
    """
    Main orchestrator for SecOps Helper analysis.
    Auto-detects input and runs appropriate tools.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.detector = InputDetector()
        self.scorer = RiskScorer()
        self.reporter = Reporter()

        # Track which tools are available
        self._check_tool_availability()

    def _check_tool_availability(self):
        """Check which tools are available."""
        self.available_tools = {}

        # Check each tool directory
        base_path = Path(__file__).parent.parent

        tool_paths = {
            'hash_lookup': base_path / 'hashLookup' / 'lookup.py',
            'ioc_extractor': base_path / 'iocExtractor' / 'extractor.py',
            'domain_intel': base_path / 'domainIpIntel' / 'intel.py',
            'url_analyzer': base_path / 'urlAnalyzer' / 'analyzer.py',
            'eml_parser': base_path / 'emlAnalysis' / 'emlParser.py',
            'log_analyzer': base_path / 'logAnalysis' / 'analyzer.py',
            'pcap_analyzer': base_path / 'pcapAnalyzer' / 'analyzer.py',
            'yara_scanner': base_path / 'yaraScanner' / 'scanner.py',
            'deobfuscator': base_path / 'deobfuscator' / 'deobfuscator.py',
            'cert_analyzer': base_path / 'certAnalyzer' / 'analyzer.py',
        }

        for tool_name, tool_path in tool_paths.items():
            self.available_tools[tool_name] = tool_path.exists()

    def _log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}", file=sys.stderr)

    def analyze(self, input_value: str) -> Dict[str, Any]:
        """
        Analyze the input and return results.

        Args:
            input_value: File path, hash, IP, domain, URL, etc.

        Returns:
            Dict with analysis results
        """
        # Detect input type
        detection = self.detector.detect(input_value)
        input_type = detection['type']

        self._log(f"Detected input type: {input_type} (confidence: {detection['confidence']})")

        # Reset scorer for new analysis
        self.scorer.reset()

        # Run analysis based on input type
        tool_results = {}
        iocs = {
            'hashes': [],
            'domains': [],
            'ips': [],
            'urls': [],
            'emails': []
        }

        if input_type == InputType.EMAIL:
            tool_results, iocs = self._analyze_email(input_value)
        elif input_type in [InputType.HASH_MD5, InputType.HASH_SHA1, InputType.HASH_SHA256]:
            tool_results = self._analyze_hash(input_value)
            iocs['hashes'] = [input_value]
        elif input_type == InputType.IP:
            tool_results = self._analyze_ip(input_value)
            iocs['ips'] = [input_value]
        elif input_type == InputType.DOMAIN:
            tool_results = self._analyze_domain(input_value)
            iocs['domains'] = [input_value]
        elif input_type == InputType.URL:
            tool_results = self._analyze_url(input_value)
            iocs['urls'] = [input_value]
        elif input_type == InputType.PCAP:
            tool_results, iocs = self._analyze_pcap(input_value)
        elif input_type == InputType.LOG:
            tool_results, iocs = self._analyze_log(input_value)
        elif input_type == InputType.SCRIPT:
            tool_results, iocs = self._analyze_script(input_value)
        elif input_type == InputType.FILE:
            tool_results, iocs = self._analyze_file(input_value)
        elif input_type == InputType.IOC_LIST:
            tool_results, iocs = self._analyze_ioc_list(input_value)
        else:
            self._log(f"Unknown input type, attempting generic analysis")
            tool_results = {'error': 'Could not determine input type'}

        return {
            'input': input_value,
            'type': input_type,
            'detection': detection,
            'tool_results': tool_results,
            'iocs': iocs,
            'scorer': self.scorer
        }

    def _analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """Analyze a hash value."""
        results = {}

        if self.available_tools.get('hash_lookup'):
            try:
                self._log("Running hash lookup...")
                from hashLookup.lookup import HashLookup

                lookup = HashLookup(verbose=self.verbose)
                result = lookup.lookup(hash_value)
                results['hash_lookup'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_hash_lookup(result)

            except Exception as e:
                self._log(f"Hash lookup error: {e}")
                results['hash_lookup'] = {'error': str(e)}

        return results

    def _analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze an IP address."""
        results = {}

        if self.available_tools.get('domain_intel'):
            try:
                self._log("Running domain/IP intelligence...")
                from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

                intel = DomainIPIntel(verbose=self.verbose)
                result = intel.lookup(ip)
                results['domain_intel'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_domain_intel(result)

            except Exception as e:
                self._log(f"Domain/IP intel error: {e}")
                results['domain_intel'] = {'error': str(e)}

        return results

    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain."""
        results = {}

        if self.available_tools.get('domain_intel'):
            try:
                self._log("Running domain/IP intelligence...")
                from domainIpIntel.intel import DomainIPIntelligence as DomainIPIntel

                intel = DomainIPIntel(verbose=self.verbose)
                result = intel.lookup(domain)
                results['domain_intel'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_domain_intel(result)

            except Exception as e:
                self._log(f"Domain intel error: {e}")
                results['domain_intel'] = {'error': str(e)}

        return results

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL."""
        results = {}

        if self.available_tools.get('url_analyzer'):
            try:
                self._log("Running URL analysis...")
                from urlAnalyzer.analyzer import URLAnalyzer

                analyzer = URLAnalyzer(verbose=self.verbose)
                result = analyzer.analyze(url)
                results['url_analyzer'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_url_analysis(result)

            except Exception as e:
                self._log(f"URL analysis error: {e}")
                results['url_analyzer'] = {'error': str(e)}

        return results

    def _analyze_email(self, file_path: str) -> tuple:
        """Analyze an email file."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        # Parse the email
        if self.available_tools.get('eml_parser'):
            try:
                self._log("Parsing email...")
                from emlAnalysis.emlParser import EMLParser

                parser = EMLParser(verbose=self.verbose)
                result = parser.parse(file_path)
                results['eml_parser'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_email_analysis(result)

            except Exception as e:
                self._log(f"Email parsing error: {e}")
                results['eml_parser'] = {'error': str(e)}

        # Extract IOCs from email
        if self.available_tools.get('ioc_extractor'):
            try:
                self._log("Extracting IOCs...")
                from iocExtractor.extractor import IOCExtractor

                extractor = IOCExtractor(exclude_private_ips=True)
                ioc_result = extractor.extract_from_file(file_path)

                hash_results = ioc_result.get('hashes', {})
                iocs['hashes'] = hash_results.get('md5', []) + hash_results.get('sha1', []) + hash_results.get('sha256', [])
                iocs['domains'] = ioc_result.get('domains', [])
                iocs['ips'] = ioc_result.get('ips', [])
                iocs['urls'] = ioc_result.get('urls', [])
                iocs['emails'] = ioc_result.get('emails', [])

                results['ioc_extractor'] = ioc_result

            except Exception as e:
                self._log(f"IOC extraction error: {e}")

        # Look up extracted IOCs (limit to avoid rate limiting)
        self._lookup_extracted_iocs(iocs, results, max_lookups=5)

        return results, iocs

    def _analyze_pcap(self, file_path: str) -> tuple:
        """Analyze a PCAP file."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        if self.available_tools.get('pcap_analyzer'):
            try:
                self._log("Analyzing PCAP...")
                from pcapAnalyzer.analyzer import PCAPAnalyzer

                analyzer = PCAPAnalyzer(verbose=self.verbose)
                result = analyzer.analyze(file_path)
                results['pcap_analyzer'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_pcap_analysis(result)

                # Extract IOCs from PCAP results
                if 'ips' in result:
                    iocs['ips'] = list(result.get('ips', {}).keys())[:20]
                if 'dns_queries' in result:
                    iocs['domains'] = [q.get('query') for q in result.get('dns_queries', [])[:20]]

            except Exception as e:
                self._log(f"PCAP analysis error: {e}")
                results['pcap_analyzer'] = {'error': str(e)}

        # Look up extracted IOCs
        self._lookup_extracted_iocs(iocs, results, max_lookups=5)

        return results, iocs

    def _analyze_log(self, file_path: str) -> tuple:
        """Analyze a log file."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        if self.available_tools.get('log_analyzer'):
            try:
                self._log("Analyzing log file...")
                from logAnalysis.analyzer import LogAnalyzer

                analyzer = LogAnalyzer(verbose=self.verbose)
                result = analyzer.analyze(file_path)
                results['log_analyzer'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_log_analysis(result)

                # Extract IOCs from log results
                threats = result.get('threats', {})
                for threat_type, entries in threats.items():
                    if isinstance(entries, list):
                        for entry in entries[:10]:
                            if isinstance(entry, dict) and 'ip' in entry:
                                iocs['ips'].append(entry['ip'])

            except Exception as e:
                self._log(f"Log analysis error: {e}")
                results['log_analyzer'] = {'error': str(e)}

        return results, iocs

    def _analyze_script(self, file_path: str) -> tuple:
        """Analyze a script file (deobfuscate)."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        if self.available_tools.get('deobfuscator'):
            try:
                self._log("Deobfuscating script...")
                from deobfuscator.deobfuscator import Deobfuscator

                deob = Deobfuscator(verbose=self.verbose)
                result = deob.deobfuscate_file(file_path)
                results['deobfuscator'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_deobfuscation(result)

                # Extract IOCs from deobfuscated content
                extracted_iocs = result.get('extracted_iocs', {})
                iocs['urls'] = extracted_iocs.get('urls', [])
                iocs['domains'] = extracted_iocs.get('domains', [])
                iocs['ips'] = extracted_iocs.get('ips', [])

            except Exception as e:
                self._log(f"Deobfuscation error: {e}")
                results['deobfuscator'] = {'error': str(e)}

        # Also run IOC extraction on the file
        if self.available_tools.get('ioc_extractor'):
            try:
                from iocExtractor.extractor import IOCExtractor
                extractor = IOCExtractor(exclude_private_ips=True)
                ioc_result = extractor.extract_from_file(file_path)
                results['ioc_extractor'] = ioc_result

                # Merge with existing IOCs
                for key in ['urls', 'domains', 'ips']:
                    existing = set(iocs.get(key, []))
                    existing.update(ioc_result.get(key, []))
                    iocs[key] = list(existing)

            except Exception as e:
                self._log(f"IOC extraction error: {e}")

        # Look up extracted IOCs
        self._lookup_extracted_iocs(iocs, results, max_lookups=5)

        return results, iocs

    def _analyze_file(self, file_path: str) -> tuple:
        """Analyze a generic file."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        # Calculate file hash
        try:
            import hashlib
            with open(file_path, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()

            iocs['hashes'] = [md5, sha256]

            # Look up the hash
            hash_results = self._analyze_hash(sha256)
            results.update(hash_results)

        except Exception as e:
            self._log(f"File hash error: {e}")

        # Run YARA scan if available
        if self.available_tools.get('yara_scanner'):
            try:
                self._log("Running YARA scan...")
                from yaraScanner.scanner import YaraScanner

                scanner = YaraScanner(verbose=self.verbose)
                result = scanner.scan_file(file_path)
                results['yara_scanner'] = result

                # Add findings to scorer
                self.scorer.add_findings_from_yara_scan(result)

            except Exception as e:
                self._log(f"YARA scan error: {e}")
                results['yara_scanner'] = {'error': str(e)}

        return results, iocs

    def _analyze_ioc_list(self, file_path: str) -> tuple:
        """Analyze a file containing a list of IOCs."""
        results = {}
        iocs = {'hashes': [], 'domains': [], 'ips': [], 'urls': [], 'emails': []}

        # Extract IOCs from the file
        if self.available_tools.get('ioc_extractor'):
            try:
                self._log("Extracting IOCs from list...")
                from iocExtractor.extractor import IOCExtractor

                extractor = IOCExtractor(exclude_private_ips=True)
                ioc_result = extractor.extract_from_file(file_path)

                hash_results = ioc_result.get('hashes', {})
                iocs['hashes'] = hash_results.get('md5', []) + hash_results.get('sha1', []) + hash_results.get('sha256', [])
                iocs['domains'] = ioc_result.get('domains', [])
                iocs['ips'] = ioc_result.get('ips', [])
                iocs['urls'] = ioc_result.get('urls', [])
                iocs['emails'] = ioc_result.get('emails', [])

                results['ioc_extractor'] = ioc_result

            except Exception as e:
                self._log(f"IOC extraction error: {e}")

        # Look up extracted IOCs
        self._lookup_extracted_iocs(iocs, results, max_lookups=10)

        return results, iocs

    def _lookup_extracted_iocs(self, iocs: Dict[str, List], results: Dict[str, Any],
                                max_lookups: int = 5):
        """Look up extracted IOCs against threat intelligence."""

        lookups_done = 0

        # Look up hashes
        if iocs.get('hashes') and self.available_tools.get('hash_lookup'):
            for hash_val in iocs['hashes'][:max_lookups]:
                if lookups_done >= max_lookups:
                    break
                try:
                    hash_result = self._analyze_hash(hash_val)
                    if 'hash_lookup' not in results:
                        results['hash_lookup'] = {'results': []}
                    if isinstance(results.get('hash_lookup'), dict) and 'results' not in results['hash_lookup']:
                        results['hash_lookup'] = {'results': [results['hash_lookup']]}
                    results['hash_lookup']['results'].append(hash_result.get('hash_lookup', {}))
                    lookups_done += 1
                except Exception as e:
                    self._log(f"Hash lookup error: {e}")

        # Look up domains
        if iocs.get('domains') and self.available_tools.get('domain_intel'):
            for domain in iocs['domains'][:max_lookups - lookups_done]:
                if lookups_done >= max_lookups:
                    break
                try:
                    domain_result = self._analyze_domain(domain)
                    if 'domain_intel' not in results:
                        results['domain_intel'] = {'results': []}
                    if isinstance(results.get('domain_intel'), dict) and 'results' not in results['domain_intel']:
                        results['domain_intel'] = {'results': [results['domain_intel']]}
                    results['domain_intel']['results'].append(domain_result.get('domain_intel', {}))
                    lookups_done += 1
                except Exception as e:
                    self._log(f"Domain intel error: {e}")

        # Look up URLs
        if iocs.get('urls') and self.available_tools.get('url_analyzer'):
            for url in iocs['urls'][:max_lookups - lookups_done]:
                if lookups_done >= max_lookups:
                    break
                try:
                    url_result = self._analyze_url(url)
                    if 'url_analyzer' not in results:
                        results['url_analyzer'] = {'results': []}
                    if isinstance(results.get('url_analyzer'), dict) and 'results' not in results['url_analyzer']:
                        results['url_analyzer'] = {'results': [results['url_analyzer']]}
                    results['url_analyzer']['results'].append(url_result.get('url_analyzer', {}))
                    lookups_done += 1
                except Exception as e:
                    self._log(f"URL analysis error: {e}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='SecOps Helper - Smart Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze a suspicious email
  python -m core.analyzer suspicious.eml

  # Check a hash
  python -m core.analyzer 44d88612fea8a8f36de82e1278abb02f

  # Analyze a domain
  python -m core.analyzer malicious.com

  # Analyze with verbose output
  python -m core.analyzer suspicious.eml --verbose

  # Get JSON output
  python -m core.analyzer suspicious.eml --json

  # Quiet mode for scripting
  python -m core.analyzer suspicious.eml --quiet
        '''
    )

    parser.add_argument('input', help='Input to analyze (file, hash, IP, domain, URL)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed progress')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Minimal output (just verdict and score)')

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Create analyzer
    analyzer = Analyzer(verbose=args.verbose)

    # Run analysis
    result = analyzer.analyze(args.input)

    # Get reporter
    reporter = Reporter()

    # Format output
    if args.quiet:
        print(reporter.format_quiet(result['scorer']))
    elif args.json:
        print(reporter.format_json(
            result['input'],
            result['type'],
            result['scorer'],
            result['iocs'],
            result['tool_results']
        ))
    elif args.verbose:
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

    # Exit with appropriate code
    sys.exit(reporter.get_exit_code(result['scorer']))


if __name__ == '__main__':
    main()
