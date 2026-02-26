# Log Analysis - Feature Specification

## Overview

**Feature Name:** Log Analysis Tools
**Module:** logAnalysis
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** Medium
**Target Release:** Phase 2-3

## Purpose

The Log Analysis toolkit provides parsers and analyzers for common security log formats including web server logs, firewall logs, authentication logs, and system logs. It identifies suspicious patterns, failed authentication attempts, anomalies, and security events, generating actionable reports for SOC analysts and incident responders.

## User Stories

### Primary Use Cases

1. **As a SOC Analyst**, I want to parse Apache/Nginx access logs to identify potential web attacks and suspicious access patterns
2. **As an Incident Responder**, I need to analyze authentication logs to detect brute-force attempts and compromised accounts
3. **As a Security Engineer**, I want to identify anomalous patterns in firewall logs to detect potential intrusions
4. **As a Threat Hunter**, I need to correlate events across multiple log sources to identify attack campaigns
5. **As a System Administrator**, I want to generate summaries of security events from system logs for daily reviews

## Functional Requirements

### FR-1: Multi-Format Log Parsing
- **Description**: Parse various log formats automatically
- **Supported Formats**:
  - Apache/Nginx access logs (Combined Log Format)
  - Windows Event Logs (EVTX)
  - Linux Syslog (RFC 3164, RFC 5424)
  - Firewall logs (iptables, pfSense, Cisco ASA)
  - SSH authentication logs (auth.log, secure)
  - IDS/IPS logs (Snort, Suricata)
  - JSON logs (application logs)
  - CEF (Common Event Format)
- **Auto-Detection**: Automatically identify log format
- **Custom Parsers**: Support for custom regex patterns

### FR-2: Web Server Log Analysis
- **Description**: Analyze HTTP access logs for security events
- **Detections**:
  - SQL injection attempts
  - XSS attempts
  - Path traversal attempts
  - Suspicious user agents (scanners, bots)
  - High-frequency requests (potential DDoS)
  - 404 scanning patterns
  - Admin panel access attempts
  - Large response sizes (data exfiltration)
- **Metrics**:
  - Top IPs by request count
  - Top requested URLs
  - Status code distribution
  - Bandwidth usage per IP
  - Geographic distribution (optional GeoIP)

### FR-3: Authentication Log Analysis
- **Description**: Detect authentication-related attacks
- **Detections**:
  - Brute-force attacks (failed login threshold)
  - Successful login after multiple failures
  - Login from unusual locations
  - Login at unusual times
  - Multiple accounts from single IP
  - Privileged account usage
  - Account lockouts
- **Metrics**:
  - Failed login attempts per user/IP
  - Successful login timeline
  - Geographic login distribution
  - Account activity summary

### FR-4: Firewall Log Analysis
- **Description**: Analyze firewall logs for security events
- **Detections**:
  - Port scanning activity
  - Blocked connection patterns
  - Unusual outbound connections
  - Connection to known malicious IPs
  - Excessive denied connections
  - Protocol violations
- **Metrics**:
  - Top blocked IPs
  - Top blocked ports
  - Connection timeline
  - Rule hit counts

### FR-5: Anomaly Detection
- **Description**: Identify unusual patterns using statistical methods
- **Techniques**:
  - Frequency-based anomalies
  - Time-based anomalies (unusual hours)
  - Geographical anomalies
  - Volume anomalies (spikes)
  - Behavioral anomalies (deviation from baseline)
- **Thresholds**: Configurable sensitivity levels
- **Baseline**: Optional baseline learning mode

### FR-6: Pattern Matching
- **Description**: Search logs for specific patterns
- **Features**:
  - Regex pattern search
  - IOC matching (IPs, domains, hashes)
  - Keyword search
  - Multi-pattern matching
  - Context extraction (lines before/after match)
- **Performance**: Optimized for large log files

### FR-7: Time Range Filtering
- **Description**: Filter logs by time period
- **Options**:
  - Absolute time range (start/end datetime)
  - Relative time (last N hours/days)
  - Specific date
  - Time of day filter (e.g., only 2-4am)
- **Format Support**: Multiple datetime formats
- **Timezone**: Timezone conversion support

### FR-8: Event Correlation
- **Description**: Correlate events across logs
- **Features**:
  - Link related events by IP
  - Timeline reconstruction
  - Event chains (attack progression)
  - Cross-log correlation
- **Output**: Correlated event sequences

### FR-9: Threat Intelligence Integration
- **Description**: Enrich logs with threat intelligence
- **Features**:
  - Check IPs against threat feeds
  - Check domains against blocklists
  - Annotate known malicious indicators
  - Reputation scoring
- **Sources**:
  - AbuseIPDB
  - Emerging Threats
  - Local threat feed
  - Custom IOC lists

### FR-10: Statistical Analysis
- **Description**: Generate statistical summaries
- **Metrics**:
  - Event count by type
  - Top talkers (IPs, users, hosts)
  - Time distribution (hourly, daily patterns)
  - Status code distribution
  - Protocol distribution
  - Success/failure ratios
- **Visualization**: ASCII charts/tables

### FR-11: Alert Generation
- **Description**: Generate alerts for security events
- **Alert Types**:
  - Brute-force detected
  - Potential scanning detected
  - High-severity events
  - Threshold exceeded
  - Pattern matched
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Output**: Alert summary with details

### FR-12: Report Generation
- **Description**: Create comprehensive analysis reports
- **Formats**:
  - JSON (detailed, machine-readable)
  - HTML (interactive dashboard)
  - PDF (executive summary)
  - Markdown (documentation)
  - CSV (data export)
- **Sections**:
  - Executive summary
  - Key findings
  - Timeline of events
  - Top indicators
  - Recommendations

### FR-13: Log Normalization
- **Description**: Convert logs to common format
- **Output Format**: JSON with standardized fields
- **Standard Fields**:
  - timestamp (ISO 8601)
  - source_ip
  - destination_ip
  - source_port
  - destination_port
  - protocol
  - action (allow/deny/alert)
  - severity
  - message
- **Use Case**: Facilitate cross-log analysis

### FR-14: Large File Handling
- **Description**: Efficiently process large log files
- **Features**:
  - Streaming parser (low memory)
  - Parallel processing
  - Compressed file support (gzip, bzip2, xz)
  - Chunked processing with progress
- **Performance**: Handle multi-GB files

### FR-15: Export & Integration
- **Description**: Export analysis results for SIEM/tools
- **Formats**:
  - CEF (Common Event Format)
  - LEEF (Log Event Extended Format)
  - Syslog
  - Splunk-compatible JSON
  - Elasticsearch bulk format
- **Integration**: Direct push to SIEM (optional)

## Non-Functional Requirements

### NFR-1: Performance
- Parse 1GB log file in < 5 minutes
- Real-time processing of log streams
- Memory usage < 500MB for large files
- Concurrent processing of multiple files

### NFR-2: Accuracy
- Correct parsing of 99%+ log entries
- Minimal false positive rate (< 2%)
- Accurate timestamp parsing across timezones

### NFR-3: Scalability
- Handle log files up to 100GB
- Process directories with thousands of files
- Horizontal scaling (multiple workers)

### NFR-4: Usability
- Auto-detect log formats
- Sensible default detection rules
- Clear, actionable output
- Progress indicators for long operations

### NFR-5: Maintainability
- Modular parser architecture
- Easy to add new log formats
- Configurable detection rules
- Well-documented code

## Technical Design

### Architecture

```
┌─────────────────┐
│  Input Handler  │
│  (File/Stream)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Format         │
│  Detector       │
└────────┬────────┘
         │
         ▼
┌──────────────────────────┐
│  Parser Selector         │
│  (Route to Correct       │
│   Parser)                │
└────────┬─────────────────┘
         │
         ├──────┬──────┬──────┬──────┐
         ▼      ▼      ▼      ▼      ▼
    ┌────────────────────────────┐
    │    Log Parsers             │
    ├────────────────────────────┤
    │ - Apache/Nginx Parser      │
    │ - Syslog Parser            │
    │ - Firewall Parser          │
    │ - Windows Event Parser     │
    │ - JSON Parser              │
    └────────┬───────────────────┘
             │
             ▼
    ┌────────────────────┐
    │  Normalizer        │
    │  (Common Format)   │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────────┐
    │  Analysis Engine       │
    ├────────────────────────┤
    │ - Pattern Detector     │
    │ - Anomaly Detector     │
    │ - Threat Intel Lookup  │
    │ - Statistical Analyzer │
    └────────┬───────────────┘
             │
             ▼
    ┌────────────────────┐
    │  Alert Generator   │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  Report Generator  │
    │  (JSON/HTML/PDF)   │
    └────────────────────┘
```

### Core Parsers

#### ApacheLogParser
```python
class ApacheLogParser(LogParser):
    PATTERNS = {
        'combined': r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"',
        'common': r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+)'
    }

    def parse_line(self, line: str) -> LogEntry:
        """Parse single log line"""
```

#### SyslogParser
```python
class SyslogParser(LogParser):
    RFC3164 = r'<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<tag>\S+): (?P<message>.*)'
    RFC5424 = r'<(?P<pri>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<structured>.*?) (?P<message>.*)'

    def parse_line(self, line: str) -> LogEntry:
        """Parse syslog line"""
```

### Data Structures

```python
@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    action: Optional[str]  # allow, deny, alert
    severity: str
    message: str
    raw_line: str
    log_type: str
    metadata: Dict[str, Any]

@dataclass
class SecurityEvent:
    event_type: str  # brute_force, sql_injection, port_scan, etc.
    severity: str  # critical, high, medium, low
    timestamp: datetime
    source_ip: str
    affected_resource: str
    description: str
    evidence: List[LogEntry]
    confidence: float  # 0.0-1.0
    recommendations: List[str]

@dataclass
class AnalysisReport:
    summary: Dict[str, Any]
    timeline: List[SecurityEvent]
    statistics: Dict[str, Any]
    alerts: List[SecurityEvent]
    top_indicators: Dict[str, List[Any]]
    recommendations: List[str]
```

## Command-Line Interface

### Syntax

```bash
python logAnalysis/analyzer.py [LOG_FILE] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `log_file` | string | Yes* | Path to log file or directory |

*Can use stdin with `-`

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--type` | `-t` | string | auto | Log type (apache/nginx/syslog/firewall/windows/auto) |
| `--analysis` | `-a` | string | all | Analysis type (web/auth/firewall/anomaly/all) |
| `--start-time` | | datetime | - | Start of time range |
| `--end-time` | | datetime | - | End of time range |
| `--last` | | string | - | Last N hours/days (e.g., "24h", "7d") |
| `--pattern` | `-p` | string | - | Search for pattern (regex) |
| `--ioc-file` | | string | - | File with IOCs to match |
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | `-f` | string | json | Output format (json/html/pdf/csv/md) |
| `--severity` | | string | all | Minimum severity (critical/high/medium/low) |
| `--alerts-only` | | flag | False | Show only alerts |
| `--normalize` | | flag | False | Output normalized logs |
| `--stats` | | flag | True | Include statistics |
| `--top` | | int | 10 | Number of top items in stats |
| `--verbose` | `-v` | flag | False | Verbose output |
| `--threads` | | int | 4 | Worker threads for parallel processing |

### Examples

#### Basic Analysis
```bash
# Auto-detect and analyze Apache logs
python logAnalysis/analyzer.py /var/log/apache2/access.log

# Analyze with specific type
python logAnalysis/analyzer.py /var/log/secure --type syslog -a auth
```

#### Time-Based Analysis
```bash
# Last 24 hours
python logAnalysis/analyzer.py access.log --last 24h

# Specific time range
python logAnalysis/analyzer.py access.log --start-time "2025-11-18 00:00" --end-time "2025-11-18 23:59"
```

#### Pattern Matching
```bash
# Search for SQL injection attempts
python logAnalysis/analyzer.py access.log --pattern "UNION.*SELECT"

# Match against IOC list
python logAnalysis/analyzer.py access.log --ioc-file threat_iocs.txt
```

#### Output Formats
```bash
# Generate HTML report
python logAnalysis/analyzer.py access.log -f html -o report.html

# Export to CSV
python logAnalysis/analyzer.py access.log -f csv -o events.csv

# Generate PDF executive report
python logAnalysis/analyzer.py access.log -f pdf -o security_report.pdf
```

#### Authentication Analysis
```bash
# Detect brute-force attacks
python logAnalysis/analyzer.py /var/log/auth.log --type syslog --analysis auth

# Show only critical alerts
python logAnalysis/analyzer.py /var/log/secure --analysis auth --severity critical --alerts-only
```

#### Firewall Analysis
```bash
# Analyze iptables logs
python logAnalysis/analyzer.py /var/log/iptables.log --type firewall --analysis firewall

# Top 20 blocked IPs
python logAnalysis/analyzer.py firewall.log --type firewall --top 20
```

#### Batch Processing
```bash
# Analyze all logs in directory
python logAnalysis/analyzer.py /var/log/apache2/ -o combined_report.html

# Process compressed logs
python logAnalysis/analyzer.py access.log.gz --last 7d
```

## Output Schema

### JSON Format

```json
{
  "metadata": {
    "analysis_date": "2025-11-18T10:00:00Z",
    "log_file": "/var/log/apache2/access.log",
    "log_type": "apache",
    "analysis_type": "web",
    "time_range": {
      "start": "2025-11-17T00:00:00Z",
      "end": "2025-11-18T00:00:00Z"
    },
    "total_entries": 150243,
    "analyzed_entries": 150243
  },
  "summary": {
    "total_events": 247,
    "alerts": {
      "critical": 3,
      "high": 12,
      "medium": 45,
      "low": 187
    },
    "top_attack_types": {
      "sql_injection": 85,
      "path_traversal": 42,
      "scanner_activity": 68,
      "xss_attempt": 52
    }
  },
  "alerts": [
    {
      "id": "alert_001",
      "event_type": "sql_injection",
      "severity": "high",
      "timestamp": "2025-11-18T08:45:23Z",
      "source_ip": "192.0.2.50",
      "affected_resource": "/admin/login.php",
      "description": "Multiple SQL injection attempts detected from 192.0.2.50",
      "confidence": 0.95,
      "evidence_count": 15,
      "evidence": [
        {
          "timestamp": "2025-11-18T08:45:23Z",
          "request": "GET /admin/login.php?id=1' UNION SELECT * FROM users-- HTTP/1.1",
          "status": 500,
          "user_agent": "sqlmap/1.5"
        }
      ],
      "recommendations": [
        "Block source IP 192.0.2.50",
        "Review application input validation",
        "Check for successful exploitation attempts"
      ],
      "threat_intel": {
        "ip_reputation": "malicious",
        "abuseipdb_score": 100,
        "known_scanner": true
      }
    }
  ],
  "statistics": {
    "top_source_ips": [
      {"ip": "192.0.2.50", "count": 1523, "flagged": true},
      {"ip": "198.51.100.25", "count": 856, "flagged": false}
    ],
    "top_requested_urls": [
      {"/index.html": 25432},
      {"/api/users": 8234}
    ],
    "status_code_distribution": {
      "200": 142340,
      "404": 5234,
      "500": 1245,
      "403": 1424
    },
    "hourly_distribution": {
      "00": 2341,
      "01": 1234,
      "...": "..."
    },
    "user_agent_analysis": {
      "browsers": 145230,
      "bots": 3245,
      "scanners": 1768
    }
  },
  "timeline": [
    {
      "timestamp": "2025-11-18T08:45:00Z",
      "event_count": 15,
      "event_types": ["sql_injection"],
      "source_ip": "192.0.2.50"
    }
  ],
  "recommendations": [
    "Implement rate limiting for /admin/* endpoints",
    "Block IPs with confirmed attack activity",
    "Update WAF rules to block SQL injection patterns",
    "Review and patch vulnerable endpoints"
  ]
}
```

## Configuration File

### YAML Format (log-analysis-config.yaml)

```yaml
parsers:
  apache:
    enabled: true
    format: combined
    datetime_format: "%d/%b/%Y:%H:%M:%S %z"

  syslog:
    enabled: true
    rfc: 5424

  firewall:
    enabled: true
    vendor: iptables

detection:
  web_attacks:
    sql_injection:
      enabled: true
      patterns:
        - "UNION.*SELECT"
        - "1=1"
        - "OR 1=1"
      severity: high

    xss:
      enabled: true
      patterns:
        - "<script"
        - "javascript:"
        - "onerror="
      severity: medium

    path_traversal:
      enabled: true
      patterns:
        - "\\.\\./\\.\\."
        - "/etc/passwd"
      severity: high

  brute_force:
    failed_login_threshold: 5
    time_window: 300  # seconds
    severity: high

  port_scan:
    connection_threshold: 20
    time_window: 60
    severity: medium

threat_intelligence:
  enabled: true
  sources:
    - abuseipdb
  api_keys:
    abuseipdb: ${ABUSEIPDB_KEY}

reporting:
  include_recommendations: true
  max_evidence_per_alert: 10
  stats_top_n: 10

performance:
  chunk_size: 10000
  workers: 4
  streaming: true
```

## Dependencies

### Required Libraries
```
python-dateutil>=2.8.0    # Date parsing
regex>=2023.0.0           # Advanced regex
pandas>=2.0.0             # Data analysis (optional)
tabulate>=0.9.0           # Table formatting
```

### Optional
```
geoip2>=4.7.0             # GeoIP lookups
reportlab>=4.0.0          # PDF generation
jinja2>=3.1.0             # HTML templates
plotly>=5.17.0            # Interactive charts
```

## Testing

### Test Cases

1. **TC-1: Apache Log Parsing**
   - Input: Standard Apache combined log
   - Expected: All fields parsed correctly

2. **TC-2: SQL Injection Detection**
   - Input: Logs with SQL injection attempts
   - Expected: Alerts generated with high confidence

3. **TC-3: Brute-Force Detection**
   - Input: Auth logs with failed login patterns
   - Expected: Brute-force alert generated

4. **TC-4: Large File Processing**
   - Input: 10GB log file
   - Expected: Processed in < 30 minutes

5. **TC-5: Time Range Filtering**
   - Input: Logs with --last 24h
   - Expected: Only last 24 hours analyzed

6. **TC-6: Multi-Format Detection**
   - Input: Directory with mixed log formats
   - Expected: Each format detected and parsed correctly

## Future Enhancements

1. **Machine Learning Anomaly Detection**
   - Train on normal patterns
   - Auto-detect unusual behavior

2. **Real-Time Log Monitoring**
   - Tail log files continuously
   - Real-time alerting

3. **SIEM Integration**
   - Direct push to Splunk, ELK
   - Bi-directional sync

4. **Attack Chain Reconstruction**
   - Link related events
   - Visualize attack progression

5. **Automated Response**
   - Auto-block IPs
   - Trigger incident response workflows

6. **Natural Language Queries**
   - "Show me all failed SSH logins from China"
   - Query logs conversationally

## Known Limitations

- Requires well-formed log entries
- Custom log formats need manual pattern configuration
- Large files require significant processing time
- GeoIP requires separate database download

## Security Considerations

- No modification of original log files
- Safe handling of malicious payloads in logs
- Input sanitization for patterns
- Secure storage of API keys

## References

- [Apache Log Format](https://httpd.apache.org/docs/current/logs.html)
- [Syslog RFC 5424](https://tools.ietf.org/html/rfc5424)
- [Common Event Format (CEF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
