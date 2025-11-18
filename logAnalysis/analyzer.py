#!/usr/bin/env python3
"""
Log Analysis - Parse and analyze security logs for threats
Supports Apache, Nginx, Syslog, and authentication logs
"""

import re
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from collections import defaultdict, Counter


class LogParser:
    """Base class for log parsers"""

    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line"""
        raise NotImplementedError


class ApacheLogParser(LogParser):
    """Parse Apache/Nginx combined log format"""

    # Combined log format pattern
    PATTERN = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse Apache/Nginx log line"""
        match = self.PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                data['timestamp'],
                '%d/%b/%Y:%H:%M:%S %z'
            )
        except ValueError:
            timestamp = None

        return {
            'timestamp': timestamp,
            'source_ip': data['ip'],
            'method': data['method'],
            'path': data['path'],
            'status': int(data['status']),
            'size': data['size'] if data['size'] != '-' else '0',
            'referer': data['referer'],
            'user_agent': data['user_agent'],
            'log_type': 'apache'
        }


class SyslogParser(LogParser):
    """Parse Syslog format (auth.log, secure)"""

    # Simplified syslog pattern
    PATTERN = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\d+:\d+:\d+) '
        r'(?P<host>\S+) (?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: '
        r'(?P<message>.*)'
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse syslog line"""
        match = self.PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp (assume current year)
        try:
            current_year = datetime.now().year
            timestamp_str = f"{data['month']} {data['day']} {current_year} {data['time']}"
            timestamp = datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
        except ValueError:
            timestamp = None

        return {
            'timestamp': timestamp,
            'host': data['host'],
            'process': data['process'],
            'pid': data.get('pid'),
            'message': data['message'],
            'log_type': 'syslog'
        }


class ThreatDetector:
    """Detect security threats in logs"""

    # Attack patterns
    SQL_INJECTION_PATTERNS = [
        r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
        r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
        r"(?i)(exec\s*\(|execute\s*\()",
        r"['\"];?\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./\.\./",
        r"\.\.\\\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
    ]

    BRUTE_FORCE_KEYWORDS = [
        "Failed password",
        "authentication failure",
        "Invalid user",
        "Failed login",
    ]

    def __init__(self):
        self.sql_regex = [re.compile(p) for p in self.SQL_INJECTION_PATTERNS]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.path_regex = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]

    def detect_sql_injection(self, text: str) -> bool:
        """Detect SQL injection attempts"""
        return any(pattern.search(text) for pattern in self.sql_regex)

    def detect_xss(self, text: str) -> bool:
        """Detect XSS attempts"""
        return any(pattern.search(text) for pattern in self.xss_regex)

    def detect_path_traversal(self, text: str) -> bool:
        """Detect path traversal attempts"""
        return any(pattern.search(text) for pattern in self.path_regex)

    def detect_brute_force(self, message: str) -> bool:
        """Detect brute force attempts"""
        return any(keyword.lower() in message.lower() for keyword in self.BRUTE_FORCE_KEYWORDS)

    def analyze_web_log(self, entry: Dict) -> List[Dict]:
        """Analyze web log entry for attacks"""
        alerts = []

        path = entry.get('path', '')
        user_agent = entry.get('user_agent', '')

        # Check for SQL injection
        if self.detect_sql_injection(path):
            alerts.append({
                'type': 'sql_injection',
                'severity': 'high',
                'description': f"SQL injection attempt detected in path: {path[:100]}",
                'source_ip': entry.get('source_ip'),
                'timestamp': entry.get('timestamp')
            })

        # Check for XSS
        if self.detect_xss(path):
            alerts.append({
                'type': 'xss',
                'severity': 'medium',
                'description': f"XSS attempt detected in path: {path[:100]}",
                'source_ip': entry.get('source_ip'),
                'timestamp': entry.get('timestamp')
            })

        # Check for path traversal
        if self.detect_path_traversal(path):
            alerts.append({
                'type': 'path_traversal',
                'severity': 'high',
                'description': f"Path traversal attempt detected: {path[:100]}",
                'source_ip': entry.get('source_ip'),
                'timestamp': entry.get('timestamp')
            })

        # Check for scanning (404s)
        if entry.get('status') == 404:
            alerts.append({
                'type': '404_scan',
                'severity': 'low',
                'description': f"404 response for {path}",
                'source_ip': entry.get('source_ip'),
                'timestamp': entry.get('timestamp')
            })

        # Suspicious user agents
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'nessus']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            alerts.append({
                'type': 'scanner_detected',
                'severity': 'medium',
                'description': f"Suspicious user agent: {user_agent}",
                'source_ip': entry.get('source_ip'),
                'timestamp': entry.get('timestamp')
            })

        return alerts

    def analyze_auth_log(self, entry: Dict) -> List[Dict]:
        """Analyze authentication log for brute force"""
        alerts = []

        message = entry.get('message', '')

        if self.detect_brute_force(message):
            alerts.append({
                'type': 'brute_force_attempt',
                'severity': 'medium',
                'description': message[:200],
                'host': entry.get('host'),
                'timestamp': entry.get('timestamp')
            })

        return alerts


class LogAnalyzer:
    """Main log analysis orchestrator"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.detector = ThreatDetector()
        self.parsers = {
            'apache': ApacheLogParser(),
            'nginx': ApacheLogParser(),  # Same format
            'syslog': SyslogParser(),
        }

    def detect_format(self, sample_lines: List[str]) -> str:
        """Auto-detect log format"""
        for line in sample_lines[:10]:
            # Try Apache/Nginx
            if re.match(r'^\S+ \S+ \S+ \[[^\]]+\]', line):
                return 'apache'

            # Try Syslog
            if re.match(r'^\w+\s+\d+ \d+:\d+:\d+', line):
                return 'syslog'

        return 'unknown'

    def analyze_file(self, file_path: str, log_type: str = 'auto') -> Dict:
        """Analyze log file"""
        if not Path(file_path).exists():
            return {'error': f'File not found: {file_path}'}

        # Read file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        if not lines:
            return {'error': 'Empty log file'}

        # Auto-detect format
        if log_type == 'auto':
            log_type = self.detect_format(lines)
            if self.verbose:
                print(f"Detected log format: {log_type}", file=sys.stderr)

        if log_type not in self.parsers:
            return {'error': f'Unsupported log type: {log_type}'}

        parser = self.parsers[log_type]

        # Parse logs
        entries = []
        for i, line in enumerate(lines, 1):
            if self.verbose and i % 1000 == 0:
                print(f"Processed {i}/{len(lines)} lines...", file=sys.stderr)

            entry = parser.parse_line(line.strip())
            if entry:
                entries.append(entry)

        if not entries:
            return {'error': 'No valid log entries parsed'}

        if self.verbose:
            print(f"Parsed {len(entries)} log entries", file=sys.stderr)

        # Analyze entries
        all_alerts = []

        for entry in entries:
            if log_type in ['apache', 'nginx']:
                alerts = self.detector.analyze_web_log(entry)
            elif log_type == 'syslog':
                alerts = self.detector.analyze_auth_log(entry)
            else:
                alerts = []

            all_alerts.extend(alerts)

        # Generate statistics
        stats = self._generate_statistics(entries, log_type)

        # Compile results
        result = {
            'metadata': {
                'log_file': file_path,
                'log_type': log_type,
                'total_entries': len(entries),
                'total_alerts': len(all_alerts),
                'analysis_date': datetime.now().isoformat()
            },
            'summary': {
                'alerts_by_type': self._count_by_type(all_alerts),
                'alerts_by_severity': self._count_by_severity(all_alerts)
            },
            'statistics': stats,
            'alerts': all_alerts[:100],  # Limit to first 100 alerts
        }

        return result

    def _generate_statistics(self, entries: List[Dict], log_type: str) -> Dict:
        """Generate statistics from log entries"""
        stats = {}

        if log_type in ['apache', 'nginx']:
            # Web log statistics
            ips = [e['source_ip'] for e in entries]
            paths = [e['path'] for e in entries]
            statuses = [e['status'] for e in entries]
            user_agents = [e['user_agent'] for e in entries]

            ip_counter = Counter(ips)
            path_counter = Counter(paths)
            status_counter = Counter(statuses)

            stats = {
                'top_ips': [
                    {'ip': ip, 'count': count}
                    for ip, count in ip_counter.most_common(10)
                ],
                'top_paths': [
                    {'path': path, 'count': count}
                    for path, count in path_counter.most_common(10)
                ],
                'status_codes': dict(status_counter),
                'total_requests': len(entries)
            }

        elif log_type == 'syslog':
            # Syslog statistics
            hosts = [e['host'] for e in entries]
            processes = [e['process'] for e in entries]

            host_counter = Counter(hosts)
            process_counter = Counter(processes)

            stats = {
                'top_hosts': [
                    {'host': host, 'count': count}
                    for host, count in host_counter.most_common(10)
                ],
                'top_processes': [
                    {'process': proc, 'count': count}
                    for proc, count in process_counter.most_common(10)
                ],
                'total_events': len(entries)
            }

        return stats

    def _count_by_type(self, alerts: List[Dict]) -> Dict:
        """Count alerts by type"""
        counter = Counter(alert['type'] for alert in alerts)
        return dict(counter)

    def _count_by_severity(self, alerts: List[Dict]) -> Dict:
        """Count alerts by severity"""
        counter = Counter(alert['severity'] for alert in alerts)
        return dict(counter)


def format_output_json(results: Dict) -> str:
    """Format results as JSON"""
    return json.dumps(results, indent=2, default=str)


def format_output_csv(results: Dict) -> str:
    """Format alerts as CSV"""
    lines = ['Type,Severity,Description,Source,Timestamp']

    for alert in results.get('alerts', []):
        alert_type = alert.get('type', '')
        severity = alert.get('severity', '')
        description = alert.get('description', '').replace(',', ';')
        source = alert.get('source_ip') or alert.get('host', '')
        timestamp = alert.get('timestamp', '')

        lines.append(f'{alert_type},{severity},{description},{source},{timestamp}')

    return '\n'.join(lines)


def format_output_text(results: Dict) -> str:
    """Format results as plain text report"""
    lines = []

    # Header
    lines.append("=" * 60)
    lines.append("LOG ANALYSIS REPORT")
    lines.append("=" * 60)

    metadata = results.get('metadata', {})
    lines.append(f"\nLog File: {metadata.get('log_file')}")
    lines.append(f"Log Type: {metadata.get('log_type')}")
    lines.append(f"Total Entries: {metadata.get('total_entries')}")
    lines.append(f"Total Alerts: {metadata.get('total_alerts')}")
    lines.append(f"Analysis Date: {metadata.get('analysis_date')}")

    # Summary
    summary = results.get('summary', {})
    lines.append("\n" + "=" * 60)
    lines.append("ALERT SUMMARY")
    lines.append("=" * 60)

    alerts_by_type = summary.get('alerts_by_type', {})
    if alerts_by_type:
        lines.append("\nAlerts by Type:")
        for alert_type, count in sorted(alerts_by_type.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {alert_type}: {count}")

    alerts_by_severity = summary.get('alerts_by_severity', {})
    if alerts_by_severity:
        lines.append("\nAlerts by Severity:")
        for severity, count in alerts_by_severity.items():
            lines.append(f"  {severity}: {count}")

    # Statistics
    stats = results.get('statistics', {})
    lines.append("\n" + "=" * 60)
    lines.append("STATISTICS")
    lines.append("=" * 60)

    if 'top_ips' in stats:
        lines.append("\nTop 10 Source IPs:")
        for item in stats['top_ips']:
            lines.append(f"  {item['ip']}: {item['count']} requests")

    if 'top_paths' in stats:
        lines.append("\nTop 10 Requested Paths:")
        for item in stats['top_paths'][:10]:
            lines.append(f"  {item['path']}: {item['count']} requests")

    if 'status_codes' in stats:
        lines.append("\nHTTP Status Codes:")
        for status, count in sorted(stats['status_codes'].items()):
            lines.append(f"  {status}: {count}")

    # Top Alerts
    alerts = results.get('alerts', [])
    if alerts:
        lines.append("\n" + "=" * 60)
        lines.append(f"TOP ALERTS (showing first 20 of {len(alerts)})")
        lines.append("=" * 60)

        for i, alert in enumerate(alerts[:20], 1):
            lines.append(f"\n{i}. [{alert['severity'].upper()}] {alert['type']}")
            lines.append(f"   {alert['description'][:100]}")
            lines.append(f"   Source: {alert.get('source_ip') or alert.get('host', 'N/A')}")
            lines.append(f"   Time: {alert.get('timestamp')}")

    return '\n'.join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Log Analysis - Parse and analyze security logs for threats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze Apache access log
  python analyzer.py /var/log/apache2/access.log

  # Analyze with specific log type
  python analyzer.py /var/log/secure --type syslog

  # Export to CSV
  python analyzer.py access.log --format csv --output alerts.csv

  # Text report
  python analyzer.py access.log --format txt --output report.txt
        '''
    )

    parser.add_argument(
        'log_file',
        help='Path to log file to analyze'
    )

    parser.add_argument(
        '--type', '-t',
        choices=['auto', 'apache', 'nginx', 'syslog'],
        default='auto',
        help='Log type (default: auto-detect)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file (default: stdout)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['json', 'csv', 'txt'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Initialize analyzer
    analyzer = LogAnalyzer(verbose=args.verbose)

    # Analyze log file
    if args.verbose:
        print(f"Analyzing {args.log_file}...", file=sys.stderr)

    results = analyzer.analyze_file(args.log_file, args.type)

    # Check for errors
    if 'error' in results:
        print(f"Error: {results['error']}", file=sys.stderr)
        sys.exit(1)

    # Format output
    if args.format == 'json':
        output = format_output_json(results)
    elif args.format == 'csv':
        output = format_output_csv(results)
    elif args.format == 'txt':
        output = format_output_text(results)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        if args.verbose:
            print(f"\nOutput written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Print summary to stderr if verbose
    if args.verbose:
        metadata = results.get('metadata', {})
        print(f"\nAnalyzed {metadata.get('total_entries')} log entries", file=sys.stderr)
        print(f"Found {metadata.get('total_alerts')} alerts", file=sys.stderr)


if __name__ == '__main__':
    main()
