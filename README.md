# SecOps Helper

[![Tests](https://github.com/Vligai/secops-helper/workflows/Tests/badge.svg)](https://github.com/Vligai/secops-helper/actions)
[![codecov](https://codecov.io/gh/Vligai/secops-helper/branch/main/graph/badge.svg)](https://codecov.io/gh/Vligai/secops-helper)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A collection of security operations tools to streamline and automate everyday security analyst tasks.

## Overview

SecOps Helper provides command-line utilities for threat analysis, incident response, and security investigations. Each tool is designed to be simple, fast, and effective for SOC analysts and security researchers.

## Available Tools

### 1. EML Parser

Analyze email files (.eml) to extract metadata, headers, attachments, and threat indicators.

**Location:** `emlAnalysis/emlParser.py`

**Features:**
- Extract email headers (From, To, Subject, etc.)
- Track IP addresses and mail relay servers
- Validate SPF/DKIM/DMARC authentication
- Extract attachment metadata and hashes
- Optional VirusTotal scanning for attachments
- JSON output for integration with other tools

**Usage:**
```bash
python emlAnalysis/emlParser.py <email.eml> [--vt] [--output report.json] [--verbose]
```

**Example:**
```bash
# Basic analysis
python emlAnalysis/emlParser.py suspicious_email.eml

# With VirusTotal scanning
python emlAnalysis/emlParser.py phishing.eml --vt --output report.json
```

---

### 2. IOC Extractor

Extract Indicators of Compromise (IOCs) from text sources including reports, logs, and documents.

**Location:** `iocExtractor/extractor.py`

**Features:**
- Extract IPs (IPv4/IPv6), domains, URLs, emails
- Extract file hashes (MD5, SHA1, SHA256, SHA512)
- Extract CVE identifiers
- Defang/refang IOCs for safe sharing
- Filter private IPs and whitelisted domains
- Export to JSON, CSV, or plain text

**Usage:**
```bash
python iocExtractor/extractor.py [input_file] [--types ip,domain,url] [--format json|csv|txt]
```

**Examples:**
```bash
# Extract all IOCs from a file
python iocExtractor/extractor.py threat_report.txt

# Extract only IPs and domains
python iocExtractor/extractor.py report.txt --types ip,domain

# Defang IOCs for safe sharing
python iocExtractor/extractor.py report.txt --defang --output safe_iocs.txt

# Export to CSV
python iocExtractor/extractor.py report.txt --format csv --output iocs.csv

# Exclude private IPs
python iocExtractor/extractor.py logs.txt --no-private-ips
```

---

### 3. Hash Lookup

Bulk file hash queries against threat intelligence sources with caching and rate limiting.

**Location:** `hashLookup/lookup.py`

**Features:**
- Query VirusTotal and MalwareBazaar APIs
- Batch processing with rate limiting
- SQLite caching for efficiency
- Verdict classification (malicious/suspicious/clean/unknown)
- Export to JSON or CSV
- Filter results by verdict

**Usage:**
```bash
python hashLookup/lookup.py [hash1] [hash2] ... [--file hashes.txt] [--format json|csv]
```

**Examples:**
```bash
# Lookup single hash
python hashLookup/lookup.py 5d41402abc4b2a76b9719d911017c592

# Lookup from file
python hashLookup/lookup.py --file hashes.txt

# Export to CSV
python hashLookup/lookup.py --file hashes.txt --format csv --output results.csv

# Show only malicious hashes
python hashLookup/lookup.py --file hashes.txt --filter malicious

# Adjust rate limiting (default: 4 req/min for VT free tier)
python hashLookup/lookup.py --file hashes.txt --rate-limit 4
```

**API Keys Required:**
- `VT_API_KEY` - VirusTotal API key (optional, but recommended)

---

### 4. Domain/IP Intelligence

Comprehensive threat intelligence and reputation analysis for domains and IP addresses.

**Location:** `domainIpIntel/intel.py`

**Features:**
- DNS resolution (A records, reverse DNS)
- Threat intelligence from VirusTotal and AbuseIPDB
- Risk scoring and classification
- Automatic IP vs domain detection
- Batch processing support
- Export to JSON or CSV

**Usage:**
```bash
python domainIpIntel/intel.py [target] [--file targets.txt] [--format json|csv]
```

**Examples:**
```bash
# Analyze IP address
python domainIpIntel/intel.py 8.8.8.8

# Analyze domain
python domainIpIntel/intel.py example.com

# Batch analysis from file
python domainIpIntel/intel.py --file targets.txt --format csv --output results.csv

# With verbose output
python domainIpIntel/intel.py suspicious-domain.com --verbose
```

**API Keys (Optional):**
- `VT_API_KEY` - VirusTotal API key
- `ABUSEIPDB_KEY` - AbuseIPDB API key

---

### 5. Log Analysis

Parse and analyze security logs to detect attacks and suspicious patterns.

**Location:** `logAnalysis/analyzer.py`

**Features:**
- Auto-detect log format (Apache, Nginx, Syslog)
- Detect web attacks (SQL injection, XSS, path traversal)
- Detect authentication attacks (brute-force attempts)
- Scanner detection (suspicious user agents)
- Traffic statistics and top talkers
- Export to JSON, CSV, or text report

**Usage:**
```bash
python logAnalysis/analyzer.py [log_file] [--type auto|apache|nginx|syslog] [--format json|csv|txt]
```

**Examples:**
```bash
# Analyze Apache access log (auto-detect format)
python logAnalysis/analyzer.py /var/log/apache2/access.log

# Analyze with specific type
python logAnalysis/analyzer.py /var/log/secure --type syslog

# Generate text report
python logAnalysis/analyzer.py access.log --format txt --output report.txt

# Export alerts to CSV
python logAnalysis/analyzer.py access.log --format csv --output alerts.csv

# Verbose analysis
python logAnalysis/analyzer.py access.log --verbose
```

**Detections:**
- SQL injection attempts
- Cross-site scripting (XSS)
- Path traversal attacks
- Brute-force authentication attempts
- Scanner activity (sqlmap, nikto, nmap)
- 404 scanning patterns

---

### 6. PCAP Analyzer

Analyze network traffic from packet capture files to identify threats and patterns.

**Location:** `pcapAnalyzer/analyzer.py`

**Features:**
- Parse PCAP/PCAPNG files
- Protocol distribution analysis
- Traffic statistics (top IPs, ports, conversations)
- DNS query analysis
- Threat detection (port scans, suspicious domains, DGA)
- HTTP payload inspection
- Export to JSON, CSV, or text report

**Usage:**
```bash
python pcapAnalyzer/analyzer.py [pcap_file] [--format json|csv|txt]
```

**Examples:**
```bash
# Analyze PCAP file
python pcapAnalyzer/analyzer.py capture.pcap

# Generate text report
python pcapAnalyzer/analyzer.py capture.pcap --format txt --output report.txt

# Export alerts to CSV
python pcapAnalyzer/analyzer.py capture.pcap --format csv --output alerts.csv

# Verbose analysis
python pcapAnalyzer/analyzer.py capture.pcap --verbose
```

**Detections:**
- Port scanning activity
- Suspicious DNS queries (DGA domains, suspicious TLDs)
- HTTP-based attacks (SQL injection, XSS in payloads)
- Unusual traffic patterns

**Dependencies:**
- Requires `scapy` library: `pip install scapy`

---

## Configuration

Create a `.env` file in the project root for API keys:

```env
# VirusTotal API (used by EML Parser, Hash Lookup, Domain/IP Intel)
VT_API_KEY=your_virustotal_api_key

# AbuseIPDB API (used by Domain/IP Intel)
ABUSEIPDB_KEY=your_abuseipdb_api_key
```

**Getting API Keys:**
- VirusTotal: Sign up at [https://www.virustotal.com/](https://www.virustotal.com/) (free tier: 4 requests/minute)
- AbuseIPDB: Sign up at [https://www.abuseipdb.com/](https://www.abuseipdb.com/) (free tier available)

## Installation

```bash
# Clone the repository
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

## Project Documentation

Complete project specifications and feature documentation available in the [openspec/](openspec/) directory:

- [Project Specification](openspec/project.openspec.md) - Overall project architecture and roadmap
- **Implemented Tools:**
  - [EML Parser Spec](openspec/specs/eml-parser.spec.md) - Email analysis tool
  - [IOC Extractor Spec](openspec/specs/ioc-extractor.spec.md) - Indicator extraction
  - [Hash Lookup Spec](openspec/specs/hash-lookup.spec.md) - Hash threat intelligence
  - [Domain/IP Intel Spec](openspec/specs/domain-ip-intel.spec.md) - Network intelligence
  - [Log Analysis Spec](openspec/specs/log-analysis.spec.md) - Security log analysis
  - [PCAP Analyzer Spec](openspec/specs/pcap-analyzer.spec.md) - Network traffic analysis

## Roadmap

### Phase 1 (Completed ✅)
- [x] EML Parser with VirusTotal integration

### Phase 2 (Completed ✅)
- [x] IOC Extractor (IPs, domains, hashes, URLs, CVEs)
- [x] Hash Lookup utility (VirusTotal, MalwareBazaar)
- [x] Domain/IP Intelligence (DNS, threat intel, risk scoring)

### Phase 3 (Completed ✅)
- [x] Log Analysis (Apache, Nginx, Syslog with attack detection)
- [x] PCAP Analyzer (Network traffic analysis with threat detection)

### Future Enhancements
- [ ] Web dashboard interface
- [ ] STIX 2.1 export support
- [ ] MISP integration
- [ ] Real-time log monitoring
- [ ] Machine learning-based anomaly detection
- [ ] Advanced correlation engine

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Security

This tool is designed for security analysis. Always handle malicious samples in isolated environments. Never execute extracted attachments or suspicious code.