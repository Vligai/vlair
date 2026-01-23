#!/usr/bin/env python3
"""
YARA Scanner - Malware detection and pattern matching

Comprehensive YARA scanning tool for files, directories, and memory dumps
with support for community rule sets and threat intelligence integration.
"""

import sys
import os
import json
import argparse
import hashlib
import time
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class YaraRuleManager:
    """Manage YARA rule loading, compilation, and caching"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.compiled_cache = {}

    def load_rules_from_file(self, rule_path: str) -> Optional[yara.Rules]:
        """Load and compile a single YARA rule file"""
        try:
            if self.verbose:
                print(f"Loading rule: {rule_path}", file=sys.stderr)

            rules = yara.compile(filepath=rule_path)
            return rules
        except yara.SyntaxError as e:
            print(f"Syntax error in rule {rule_path}: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error loading rule {rule_path}: {e}", file=sys.stderr)
            return None

    def load_rules_from_directory(self, dir_path: str, recursive=True) -> Optional[yara.Rules]:
        """Load and compile all YARA rules from a directory"""
        rule_files = {}
        dir_path = Path(dir_path)

        if not dir_path.exists():
            print(f"Error: Directory not found: {dir_path}", file=sys.stderr)
            return None

        # Find all .yar and .yara files
        patterns = ['*.yar', '*.yara']
        for pattern in patterns:
            if recursive:
                files = dir_path.rglob(pattern)
            else:
                files = dir_path.glob(pattern)

            for file_path in files:
                namespace = file_path.stem
                rule_files[namespace] = str(file_path)

        if not rule_files:
            print(f"Warning: No YARA rules found in {dir_path}", file=sys.stderr)
            return None

        if self.verbose:
            print(f"Found {len(rule_files)} rule files", file=sys.stderr)

        # Compile all rules
        try:
            rules = yara.compile(filepaths=rule_files)
            return rules
        except yara.SyntaxError as e:
            print(f"Syntax error in rules: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error compiling rules: {e}", file=sys.stderr)
            return None

    def validate_rule(self, rule_path: str) -> Tuple[bool, Optional[str]]:
        """Validate a YARA rule file"""
        try:
            yara.compile(filepath=rule_path)
            return True, None
        except yara.SyntaxError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    def save_compiled_rules(self, rules: yara.Rules, output_path: str) -> bool:
        """Save compiled rules to file"""
        try:
            rules.save(output_path)
            return True
        except Exception as e:
            print(f"Error saving compiled rules: {e}", file=sys.stderr)
            return False

    def load_compiled_rules(self, compiled_path: str) -> Optional[yara.Rules]:
        """Load pre-compiled rules"""
        try:
            rules = yara.load(compiled_path)
            return rules
        except Exception as e:
            print(f"Error loading compiled rules: {e}", file=sys.stderr)
            return None


class MatchAnalyzer:
    """Analyze and enrich YARA matches"""

    SEVERITY_MAP = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }

    @staticmethod
    def extract_match_info(match: yara.Match, file_path: str, file_hash: str, file_size: int) -> Dict:
        """Extract detailed information from a YARA match"""
        match_info = {
            'file_path': file_path,
            'file_hash': file_hash,
            'file_size': file_size,
            'scan_date': datetime.utcnow().isoformat() + 'Z',
            'rule_name': match.rule,
            'namespace': match.namespace if match.namespace else 'default',
            'tags': list(match.tags) if match.tags else [],
            'meta': dict(match.meta) if match.meta else {},
            'strings': []
        }

        # Extract matched strings
        for string_match in match.strings:
            for instance in string_match.instances:
                match_info['strings'].append({
                    'identifier': string_match.identifier,
                    'value': instance.matched_data.decode('utf-8', errors='replace')[:100],
                    'offset': instance.offset
                })

        # Determine severity
        match_info['severity'] = MatchAnalyzer.classify_severity(match)

        return match_info

    @staticmethod
    def classify_severity(match: yara.Match) -> str:
        """Classify match severity based on tags and metadata"""
        # Check metadata for severity
        if match.meta and 'severity' in match.meta:
            severity = match.meta['severity'].lower()
            if severity in MatchAnalyzer.SEVERITY_MAP:
                return severity

        # Check tags for severity indicators
        tags = [tag.lower() for tag in match.tags] if match.tags else []

        # Critical indicators
        critical_tags = ['apt', 'ransomware', 'rat', 'backdoor', 'rootkit', 'critical']
        if any(tag in tags for tag in critical_tags):
            return 'critical'

        # High severity indicators
        high_tags = ['trojan', 'malware', 'exploit', 'suspicious', 'high']
        if any(tag in tags for tag in high_tags):
            return 'high'

        # Medium severity
        medium_tags = ['pup', 'adware', 'medium']
        if any(tag in tags for tag in medium_tags):
            return 'medium'

        # Low severity
        low_tags = ['test', 'generic', 'low']
        if any(tag in tags for tag in low_tags):
            return 'low'

        # Default to medium
        return 'medium'

    @staticmethod
    def classify_verdict(matches: List[Dict]) -> Tuple[str, int]:
        """Classify overall verdict based on matches"""
        if not matches:
            return 'clean', 0

        # Find highest severity
        max_severity = max(
            MatchAnalyzer.SEVERITY_MAP.get(m.get('severity', 'low'), 1)
            for m in matches
        )

        # Calculate risk score
        risk_score = min(100, max_severity * 20 + len(matches) * 5)

        # Determine verdict
        if max_severity >= 4:  # Critical
            return 'malicious', risk_score
        elif max_severity >= 3:  # High
            return 'malicious', risk_score
        elif max_severity >= 2:  # Medium
            return 'suspicious', risk_score
        else:
            return 'informational', risk_score


class YaraScanner:
    """Main YARA scanning engine"""

    def __init__(self, rules: yara.Rules, verbose=False, timeout=60):
        self.rules = rules
        self.verbose = verbose
        self.timeout = timeout
        self.stats = {
            'files_scanned': 0,
            'matches_found': 0,
            'errors': 0,
            'total_time': 0
        }

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return 'unknown'

    def scan_file(self, file_path: str) -> Optional[Dict]:
        """Scan a single file with YARA rules"""
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                if self.verbose:
                    print(f"File not found: {file_path}", file=sys.stderr)
                return None

            if not file_path.is_file():
                return None

            # Get file info
            file_size = file_path.stat().st_size
            file_hash = self.calculate_file_hash(str(file_path))

            # Scan with YARA
            start_time = time.time()
            matches = self.rules.match(str(file_path), timeout=self.timeout)
            scan_time = time.time() - start_time

            self.stats['files_scanned'] += 1
            self.stats['total_time'] += scan_time

            if matches:
                self.stats['matches_found'] += len(matches)

                # Extract match details
                match_details = []
                for match in matches:
                    detail = MatchAnalyzer.extract_match_info(
                        match, str(file_path), file_hash, file_size
                    )
                    match_details.append(detail)

                # Classify verdict
                verdict, risk_score = MatchAnalyzer.classify_verdict(match_details)

                return {
                    'file_path': str(file_path),
                    'file_hash': file_hash,
                    'file_size': file_size,
                    'scan_time': round(scan_time, 3),
                    'matches': match_details,
                    'verdict': verdict,
                    'risk_score': risk_score
                }

            return {
                'file_path': str(file_path),
                'file_hash': file_hash,
                'file_size': file_size,
                'scan_time': round(scan_time, 3),
                'matches': [],
                'verdict': 'clean',
                'risk_score': 0
            }

        except yara.TimeoutError:
            self.stats['errors'] += 1
            if self.verbose:
                print(f"Timeout scanning: {file_path}", file=sys.stderr)
            return None
        except Exception as e:
            self.stats['errors'] += 1
            if self.verbose:
                print(f"Error scanning {file_path}: {e}", file=sys.stderr)
            return None

    def scan_directory(self, dir_path: str, recursive=True, extensions=None,
                      max_workers=4) -> List[Dict]:
        """Scan all files in a directory"""
        dir_path = Path(dir_path)

        if not dir_path.exists():
            print(f"Error: Directory not found: {dir_path}", file=sys.stderr)
            return []

        # Collect files to scan
        files_to_scan = []

        if recursive:
            files = dir_path.rglob('*')
        else:
            files = dir_path.glob('*')

        for file_path in files:
            if file_path.is_file():
                # Filter by extension if specified
                if extensions:
                    if file_path.suffix.lower().lstrip('.') not in extensions:
                        continue
                files_to_scan.append(str(file_path))

        if not files_to_scan:
            print("No files found to scan", file=sys.stderr)
            return []

        if self.verbose:
            print(f"Scanning {len(files_to_scan)} files...", file=sys.stderr)

        # Scan files with thread pool
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_file, file_path): file_path
                for file_path in files_to_scan
            }

            # Progress bar if tqdm available
            if TQDM_AVAILABLE and not self.verbose:
                pbar = tqdm(total=len(files_to_scan), desc="Scanning", unit="files")
            else:
                pbar = None

            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

                if pbar:
                    pbar.update(1)
                elif self.verbose:
                    file_path = futures[future]
                    print(f"Scanned: {file_path}", file=sys.stderr)

            if pbar:
                pbar.close()

        return results


def format_output_json(results: List[Dict], metadata: Dict) -> str:
    """Format results as JSON"""
    # Calculate statistics
    by_verdict = defaultdict(int)
    by_severity = defaultdict(int)

    for result in results:
        verdict = result.get('verdict', 'unknown')
        by_verdict[verdict] += 1

        for match in result.get('matches', []):
            severity = match.get('severity', 'unknown')
            by_severity[severity] += 1

    output = {
        'metadata': metadata,
        'statistics': {
            'by_verdict': dict(by_verdict),
            'by_severity': dict(by_severity)
        },
        'results': results
    }

    return json.dumps(output, indent=2)


def format_output_csv(results: List[Dict]) -> str:
    """Format results as CSV"""
    lines = ['File Path,File Hash,File Size,Scan Time,Matches,Verdict,Risk Score,Matched Rules']

    for result in results:
        matches = result.get('matches', [])
        matched_rules = ';'.join([m['rule_name'] for m in matches])

        lines.append(
            f'"{result["file_path"]}",'
            f'{result["file_hash"]},'
            f'{result["file_size"]},'
            f'{result["scan_time"]},'
            f'{len(matches)},'
            f'{result["verdict"]},'
            f'{result["risk_score"]},'
            f'"{matched_rules}"'
        )

    return '\n'.join(lines)


def format_output_text(results: List[Dict]) -> str:
    """Format results as human-readable text"""
    lines = []
    lines.append("=" * 80)
    lines.append("YARA Scan Results")
    lines.append("=" * 80)
    lines.append("")

    # Summary statistics
    total_files = len(results)
    files_with_matches = sum(1 for r in results if r.get('matches'))
    total_matches = sum(len(r.get('matches', [])) for r in results)

    lines.append(f"Files Scanned: {total_files}")
    lines.append(f"Files with Matches: {files_with_matches}")
    lines.append(f"Total Matches: {total_matches}")
    lines.append("")

    # Detail results (only files with matches)
    for result in results:
        matches = result.get('matches', [])
        if not matches:
            continue

        lines.append("=" * 80)
        lines.append(f"FILE: {result['file_path']}")
        lines.append(f"HASH: {result['file_hash']}")
        lines.append(f"SIZE: {result['file_size']} bytes")
        lines.append(f"VERDICT: {result['verdict'].upper()}")
        lines.append(f"RISK SCORE: {result['risk_score']}/100")
        lines.append(f"SCAN TIME: {result['scan_time']}s")
        lines.append("")
        lines.append("Matched Rules:")

        for match in matches:
            lines.append(f"  [{match['severity'].upper()}] {match['rule_name']} ({match['namespace']})")

            if match.get('meta'):
                meta = match['meta']
                if 'description' in meta:
                    lines.append(f"    Description: {meta['description']}")
                if 'author' in meta:
                    lines.append(f"    Author: {meta['author']}")

            if match.get('tags'):
                lines.append(f"    Tags: {', '.join(match['tags'])}")

            if match.get('strings'):
                lines.append(f"    Matched Strings:")
                for string in match['strings'][:5]:  # Limit to 5
                    lines.append(f"      - {string['identifier']}: \"{string['value']}\" at offset {string['offset']}")

            lines.append("")

    lines.append("=" * 80)
    return '\n'.join(lines)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='YARA Scanner - Malware detection and pattern matching',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan single file
  python scanner.py scan suspicious.exe --rules ./rules/

  # Scan directory recursively
  python scanner.py scan /samples/ --rules ./rules/ --recursive

  # Scan with specific extensions
  python scanner.py scan /data/ --rules ./rules/ --extensions exe,dll

  # Scan and export to JSON
  python scanner.py scan /samples/ --rules ./rules/ --format json --output results.json

  # Validate rules
  python scanner.py validate ./rules/malware/trojan.yar

  # Validate all rules in directory
  python scanner.py validate ./rules/ --recursive
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files with YARA rules')
    scan_parser.add_argument('target', help='File or directory to scan')
    scan_parser.add_argument('--rules', '-r', required=True, help='YARA rule file or directory')
    scan_parser.add_argument('--recursive', action='store_true', help='Scan directories recursively')
    scan_parser.add_argument('--extensions', help='File extensions to scan (comma-separated)')
    scan_parser.add_argument('--threads', '-t', type=int, default=4, help='Number of worker threads')
    scan_parser.add_argument('--timeout', type=int, default=60, help='Timeout per file (seconds)')
    scan_parser.add_argument('--format', '-f', choices=['json', 'csv', 'txt'],
                           default='json', help='Output format')
    scan_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate YARA rules')
    validate_parser.add_argument('rules', help='YARA rule file or directory')
    validate_parser.add_argument('--recursive', action='store_true', help='Validate all rules in directory')

    return parser.parse_args()


def main():
    """Main entry point"""
    if not YARA_AVAILABLE:
        print("Error: yara-python not installed. Install with: pip install yara-python", file=sys.stderr)
        print("Note: YARA must be installed on your system first.", file=sys.stderr)
        sys.exit(1)

    args = parse_args()

    if not args.command:
        print("Error: No command specified. Use --help for usage information.", file=sys.stderr)
        sys.exit(1)

    # Validate command
    if args.command == 'validate':
        manager = YaraRuleManager(verbose=True)
        rules_path = Path(args.rules)

        if not rules_path.exists():
            print(f"Error: Rules path not found: {rules_path}", file=sys.stderr)
            sys.exit(1)

        if rules_path.is_file():
            # Validate single file
            valid, error = manager.validate_rule(str(rules_path))
            if valid:
                print(f"✓ {rules_path} - Valid")
                sys.exit(0)
            else:
                print(f"✗ {rules_path} - Invalid: {error}")
                sys.exit(1)

        elif rules_path.is_dir():
            # Validate all rules in directory
            patterns = ['*.yar', '*.yara']
            rule_files = []

            for pattern in patterns:
                if args.recursive:
                    files = rules_path.rglob(pattern)
                else:
                    files = rules_path.glob(pattern)
                rule_files.extend(files)

            if not rule_files:
                print("No YARA rule files found", file=sys.stderr)
                sys.exit(1)

            print(f"Validating {len(rule_files)} rule files...")

            valid_count = 0
            invalid_count = 0

            for rule_file in rule_files:
                valid, error = manager.validate_rule(str(rule_file))
                if valid:
                    print(f"✓ {rule_file.name}")
                    valid_count += 1
                else:
                    print(f"✗ {rule_file.name} - {error}")
                    invalid_count += 1

            print(f"\nValidation complete: {valid_count} valid, {invalid_count} invalid")
            sys.exit(0 if invalid_count == 0 else 1)

    # Scan command
    elif args.command == 'scan':
        # Load rules
        manager = YaraRuleManager(verbose=args.verbose)
        rules_path = Path(args.rules)

        if not rules_path.exists():
            print(f"Error: Rules path not found: {rules_path}", file=sys.stderr)
            sys.exit(1)

        if rules_path.is_file():
            rules = manager.load_rules_from_file(str(rules_path))
        else:
            rules = manager.load_rules_from_directory(str(rules_path), recursive=True)

        if not rules:
            print("Error: Failed to load YARA rules", file=sys.stderr)
            sys.exit(1)

        # Initialize scanner
        scanner = YaraScanner(rules, verbose=args.verbose, timeout=args.timeout)

        # Parse extensions
        extensions = None
        if args.extensions:
            extensions = [ext.strip().lower().lstrip('.') for ext in args.extensions.split(',')]

        # Scan target
        target_path = Path(args.target)

        if not target_path.exists():
            print(f"Error: Target not found: {target_path}", file=sys.stderr)
            sys.exit(1)

        start_time = time.time()

        if target_path.is_file():
            # Scan single file
            result = scanner.scan_file(str(target_path))
            results = [result] if result else []
        else:
            # Scan directory
            results = scanner.scan_directory(
                str(target_path),
                recursive=args.recursive,
                extensions=extensions,
                max_workers=args.threads
            )

        total_time = time.time() - start_time

        # Prepare metadata
        metadata = {
            'tool': 'yara_scanner',
            'version': '1.0.0',
            'scan_date': datetime.utcnow().isoformat() + 'Z',
            'target': str(target_path),
            'rules_path': str(rules_path),
            'files_scanned': scanner.stats['files_scanned'],
            'matches_found': scanner.stats['matches_found'],
            'errors': scanner.stats['errors'],
            'total_time': round(total_time, 2)
        }

        # Format output
        if args.format == 'json':
            output = format_output_json(results, metadata)
        elif args.format == 'csv':
            output = format_output_csv(results)
        else:  # txt
            output = format_output_text(results)

        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(output)

        sys.exit(0)


if __name__ == '__main__':
    main()
