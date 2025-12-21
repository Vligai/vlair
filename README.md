# SecOps Helper

[![Tests](https://github.com/Vligai/secops-helper/workflows/Tests/badge.svg)](https://github.com/Vligai/secops-helper/actions)
[![codecov](https://codecov.io/gh/Vligai/secops-helper/branch/main/graph/badge.svg)](https://codecov.io/gh/Vligai/secops-helper)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A collection of security operations tools to streamline and automate everyday security analyst tasks.

## Overview

SecOps Helper provides command-line utilities for threat analysis, incident response, and security investigations. Each tool is designed to be simple, fast, and effective for SOC analysts and security researchers.

**NEW!** SecOps Helper now features a **Central Control System** that provides:
- 🎯 **Interactive Menu** - Easy navigation and tool discovery
- 🔍 **Smart Search** - Find tools by keywords
- 📚 **Unified Documentation** - All tool info in one place
- ⚡ **Quick Access** - Single command to run any tool
- 📊 **Categorized Tools** - Browse by analysis type

## Quick Start

### Interactive Mode (Recommended)

Launch the interactive menu to browse and select tools:

```bash
./secops
```

This will present a menu where you can:
1. Browse tools by category (Email, Malware, Network, etc.)
2. Search for tools by keyword
3. View detailed tool information
4. Check API key status
5. Access the quick start guide

### Command-Line Mode

List all available tools:
```bash
./secops list
```

Get detailed information about a tool:
```bash
./secops info <tool>
```

Search for tools:
```bash
./secops search malware
```

Run a tool directly:
```bash
./secops <tool> [arguments]
```

### Common Workflows

```bash
# Analyze suspicious email
./secops eml suspicious.eml --vt

# Extract IOCs from threat report
./secops ioc report.txt --format csv --output iocs.csv

# Check hash reputation
./secops hash 44d88612fea8a8f36de82e1278abb02f

# Analyze domain/IP
./secops intel malicious.com

# Scan for malware with YARA
./secops yara scan /samples/ --rules ./yaraScanner/rules/

# Analyze SSL certificate
./secops cert https://example.com

# Deobfuscate malicious script
./secops deobfuscate malware.js --extract-iocs

# Analyze network traffic
./secops pcap capture.pcap

# Update threat feeds
./secops threatfeed update --source all

# Carve files from disk image
./secops carve --image disk.dd --output /carved/
```

## Tool Categories

SecOps Helper includes **12 specialized tools** organized by category:

| Category | Tools | Description |
|----------|-------|-------------|
| **Email Analysis** | EML Parser | Parse and analyze email files |
| **Threat Intelligence** | IOC Extractor, Hash Lookup, Domain/IP Intel, URL Analyzer, Threat Feed Aggregator | Extract and analyze threat indicators |
| **Log Analysis** | Log Analyzer | Detect attacks in web server logs |
| **Network Analysis** | PCAP Analyzer | Analyze network traffic captures |
| **SSL/TLS Analysis** | Certificate Analyzer | Analyze SSL/TLS certificates |
| **Malware Analysis** | YARA Scanner, Script Deobfuscator | Detect and analyze malware |
| **Forensics** | File Carver | Extract files from disk images |

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

### 7. URL Analyzer (New! 🔗)

Comprehensive URL threat analysis with multiple intelligence sources and pattern detection.

**Location:** `urlAnalyzer/analyzer.py`

**Features:**
- Multi-source threat intelligence (VirusTotal, URLhaus)
- URL parsing and decomposition
- Suspicious pattern detection
- Homograph attack detection
- Automatic caching for repeated lookups
- Export to JSON, CSV, or text report

**Usage:**
```bash
python urlAnalyzer/analyzer.py [url] [--format json|csv|txt]

# Or via unified CLI
secops-helper url "http://suspicious-site.com"
```

**Examples:**
```bash
# Analyze single URL
python urlAnalyzer/analyzer.py "http://suspicious-site.com"

# Analyze URLs from file
python urlAnalyzer/analyzer.py --file urls.txt --format csv

# With output file
python urlAnalyzer/analyzer.py "http://test.com" --output results.json

# Disable caching
python urlAnalyzer/analyzer.py "http://example.com" --no-cache

# Verbose mode
python urlAnalyzer/analyzer.py "http://test.com" --verbose
```

**Detection Capabilities:**
- **Threat Intelligence**: URLhaus malicious URL database, VirusTotal URL scanning
- **Suspicious Patterns**:
  - IP addresses instead of domains
  - Suspicious keywords (login, verify, banking, etc.)
  - Dangerous file extensions (.exe, .scr, .bat, etc.)
  - Excessive URL encoding (obfuscation)
  - Free/suspicious TLDs (.tk, .ml, .ga, etc.)
  - Homograph attacks (non-ASCII characters)
  - Excessive subdomains
  - Unusually long domains

**Output:**
```json
{
  "url": "http://suspicious-site.com",
  "verdict": "suspicious",
  "risk_level": "medium",
  "parsed": {
    "domain": "suspicious-site.com",
    "scheme": "http",
    "path": "/"
  },
  "pattern_analysis": {
    "suspicions": ["Contains suspicious keywords: login, verify"],
    "risk_score": 45,
    "is_suspicious": true
  },
  "threat_intelligence": {
    "virustotal": {
      "verdict": "suspicious",
      "malicious": 2,
      "suspicious": 3
    },
    "urlhaus": {
      "verdict": "unknown"
    }
  }
}
```

**API Endpoint:**
```bash
curl -X POST http://localhost:5000/api/url/analyze \
  -H "Content-Type: application/json" \
  -d '{"urls": ["http://example.com"]}'
```

**Caching:**
- Results cached in Redis (24-hour TTL)
- Cache namespace: `url_analysis`
- Significantly faster repeated lookups

---

### 8. YARA Scanner (New! 🎯)

Scan files, directories, and memory dumps with YARA rules for malware detection and pattern matching.

**Location:** `yaraScanner/scanner.py`

**Features:**
- Multi-format scanning (files, directories, PCAP, memory dumps)
- Rule validation and compilation
- Batch scanning with multi-threading
- Severity classification (critical/high/medium/low)
- Match analysis with detailed metadata extraction
- Support for community rule repositories
- Multiple output formats (JSON, CSV, TXT)

**Usage:**
```bash
# Scan file with YARA rules
python yaraScanner/scanner.py scan suspicious.exe --rules ./yaraScanner/rules/

# Scan directory recursively
python yaraScanner/scanner.py scan /samples/ --rules ./rules/ --recursive

# Validate YARA rules
python yaraScanner/scanner.py validate ./rules/malware/

# Unified CLI
secops-helper yara scan /samples/ --rules ./yaraScanner/rules/ --recursive
```

**Included Rules:**
- EICAR test file detection
- Suspicious PowerShell patterns
- Malware downloader detection
- Registry persistence mechanisms
- Anti-analysis techniques
- APT indicators (webshells, credential access, C2)

---

### 9. Certificate Analyzer (New! 🔒)

Analyze SSL/TLS certificates for security issues, phishing detection, and expiration monitoring.

**Location:** `certAnalyzer/analyzer.py`

**Features:**
- Retrieve certificates from HTTPS servers and files (PEM/DER)
- Certificate information extraction (subject, issuer, validity, SANs)
- Chain validation and hostname verification
- Security issue detection (weak crypto, small keys, expired certs)
- Phishing detection (brand impersonation, suspicious patterns)
- Certificate Transparency log queries (crt.sh)
- Risk scoring and verdict classification
- Batch domain processing

**Usage:**
```bash
# Analyze HTTPS server certificate
python certAnalyzer/analyzer.py https://example.com

# Analyze certificate file
python certAnalyzer/analyzer.py --file cert.pem --hostname example.com

# Query Certificate Transparency
python certAnalyzer/analyzer.py --ct-search example.com

# Batch analysis
python certAnalyzer/analyzer.py --file-list domains.txt --format json

# Unified CLI
secops-helper cert https://example.com
```

**Security Checks:**
- Weak signature algorithms (MD5, SHA1)
- Small RSA key sizes (< 2048 bits)
- Expired or not-yet-valid certificates
- Self-signed certificates
- Brand impersonation in CN/SAN
- Suspicious certificate patterns
- Very new certificates (< 7 days)

---

### 10. Deobfuscator (New! 🔓)

Deobfuscate malicious scripts (JavaScript, PowerShell, VBScript, Batch) and extract IOCs.

**Location:** `deobfuscator/deobfuscator.py`

**Features:**
- Multi-language support (JavaScript, PowerShell, VBScript, Batch, Python)
- Auto-detect script language
- Multi-layer deobfuscation (up to 10 layers)
- Encoding detection and decoding (Base64, Hex, URL, ROT13)
- PowerShell-specific: -EncodedCommand, backtick removal, compression
- JavaScript-specific: String.fromCharCode(), escape sequences
- Automatic IOC extraction from deobfuscated code
- Quick decode commands for one-off tasks

**Usage:**
```bash
# Deobfuscate JavaScript
python deobfuscator/deobfuscator.py malware.js --extract-iocs

# Deobfuscate PowerShell
python deobfuscator/deobfuscator.py script.ps1 --language powershell --verbose

# Quick base64 decode
python deobfuscator/deobfuscator.py --decode-base64 "SGVsbG8gV29ybGQ="

# Quick hex decode
python deobfuscator/deobfuscator.py --decode-hex "48656c6c6f"

# Unified CLI
secops-helper deobfuscate malware.js --extract-iocs
```

**Supported Techniques:**
- Base64 encoding (standard & URL-safe)
- Hex encoding
- URL encoding
- ROT13 cipher
- PowerShell encoded commands (UTF-16LE)
- PowerShell backtick obfuscation
- PowerShell Gzip compression
- JavaScript hex/unicode escapes
- JavaScript String.fromCharCode()

---

### 11. Threat Feed Aggregator (New! 📊)

Aggregate threat intelligence from multiple sources into a centralized database with deduplication and search.

**Location:** `threatFeedAggregator/aggregator.py`

**Features:**
- Multi-source threat intelligence (ThreatFox, URLhaus)
- SQLite storage with full schema
- Automatic deduplication by IOC hash
- Confidence scoring (increases with multiple sources)
- Search by value, type, malware family, confidence
- Export to JSON and CSV
- Statistics and metrics dashboard
- Update history tracking

**Usage:**
```bash
# Update all feeds
python threatFeedAggregator/aggregator.py update

# Update specific feed
python threatFeedAggregator/aggregator.py update --source threatfox --verbose

# Search for IOC
python threatFeedAggregator/aggregator.py search "malicious.com"

# Search by type
python threatFeedAggregator/aggregator.py search --type domain --min-confidence 70

# Search by malware family
python threatFeedAggregator/aggregator.py search --malware emotet --format json

# Get statistics
python threatFeedAggregator/aggregator.py stats

# Export IOCs
python threatFeedAggregator/aggregator.py export --format csv --output iocs.csv --min-confidence 80
```

**Supported Feeds:**
- Abuse.ch ThreatFox (malware C2 IOCs)
- Abuse.ch URLhaus (malicious URLs)
- Extensible for additional feeds

**Database Location:** `~/.threatFeedAggregator/feeds.db`

---

### 12. File Carver (New! 🗂️)

Extract embedded files from disk images, memory dumps, and binary files using file signature detection.

**Location:** `fileCarver/carver.py`

**Features:**
- Extract files from disk images, memory dumps, binary files
- 25+ file type signatures (images, documents, archives, executables)
- Magic bytes detection (headers and footers)
- Automatic hash calculation (MD5, SHA256)
- Organized output by file type
- Chunked processing for large files (1MB chunks)
- Progress reporting for large datasets
- Multiple output formats (JSON, CSV, TXT)

**Usage:**
```bash
# List supported file types
python fileCarver/carver.py --list-types

# Carve all file types
python fileCarver/carver.py --image disk.dd --output /carved/

# Carve specific types
python fileCarver/carver.py --image memdump.raw --types exe,dll,pdf --verbose

# Generate JSON report
python fileCarver/carver.py --image disk.dd --format json --report report.json
```

**Supported File Types (25):**
- **Images:** JPG, PNG, GIF
- **Documents:** PDF, DOC, DOCX, XLS, XLSX, EML, HTML, XML
- **Archives:** ZIP, RAR, 7Z, TAR, GZ, BZ2
- **Executables:** EXE, DLL
- **Media:** MP3, MP4, AVI
- **Scripts:** PS1, BAT
- **Databases:** SQLite

**Output Organization:**
- Files organized in type-specific subdirectories
- Filenames include file ID and SHA256 prefix
- Complete metadata in JSON/CSV reports

---

## Web Dashboard (New! 🌐)

SecOps Helper now includes a modern web interface for all tools - no command line required!

### Quick Start

```bash
# Using Docker Compose (Recommended)
docker-compose up -d web

# Open your browser to http://localhost:5000
```

### Features

The web dashboard provides:
- **Interactive Interface**: Point-and-click analysis without command line
- **Real-time Results**: Instant visualization of analysis results
- **File Upload**: Drag-and-drop support for email, log, and PCAP files
- **Multiple Tools**: 7 SecOps Helper tools in web interface (12 total via CLI)
- **Export Options**: Download results as JSON, CSV, or STIX 2.1
- **Statistics Dashboard**: Track total analyses and IOCs extracted
- **Responsive Design**: Works on desktop, tablet, and mobile devices

### Available Tools in Web UI

- **IOC Extractor** - Extract indicators from text or files
- **Hash Lookup** - Query file hashes against threat intelligence
- **Domain/IP Intel** - Analyze domains and IP addresses
- **Log Analysis** - Upload and analyze security logs
- **Email Parser** - Parse .eml files with attachment analysis

### Running the Web Dashboard

**Option 1: Docker Compose (Recommended)**

```bash
# Start all services
docker-compose up -d web

# Access dashboard
open http://localhost:5000

# View logs
docker-compose logs -f web

# Stop services
docker-compose down
```

**Option 2: Local Python**

```bash
# Install web dependencies
pip install -r requirements-webapp.txt

# Run development server
python webapp/app.py

# Production with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 webapp.app:app
```

### API Endpoints

The web dashboard also exposes a REST API:

```bash
# Health check
curl http://localhost:5000/api/health

# Extract IOCs
curl -X POST http://localhost:5000/api/ioc/extract \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact malware@evil.com at 192.0.2.1"}'

# Lookup hashes
curl -X POST http://localhost:5000/api/hash/lookup \
  -H "Content-Type: application/json" \
  -d '{"hashes": ["5d41402abc4b2a76b9719d911017c592"]}'

# Analyze domain/IP
curl -X POST http://localhost:5000/api/intel/analyze \
  -H "Content-Type: application/json" \
  -d '{"targets": ["8.8.8.8", "example.com"]}'
```

Full API documentation available in `webapp/app.py`.

---

## Unified CLI (New! 🚀)

SecOps Helper also provides a unified command-line interface for all tools:

```bash
# Install the package
pip install -e .

# Use unified CLI
secops-helper <command> [options]
```

**Available Commands:**
- `eml` - Email analysis
- `ioc` - IOC extraction
- `hash` - Hash lookup
- `intel` - Domain/IP intelligence
- `log` - Log analysis
- `pcap` - PCAP analysis
- `url` - URL threat analysis
- `yara` - YARA malware scanning
- `cert` - Certificate analysis
- `deobfuscate` - Script deobfuscation
- (Threat Feed Aggregator and File Carver use standalone CLIs)

**Examples:**
```bash
# Extract IOCs with STIX export
secops-helper ioc threat_report.txt --format stix --output iocs.json

# Batch hash lookup
secops-helper hash --file hashes.txt --format csv

# Domain reputation analysis
secops-helper intel malicious.com

# Log analysis
secops-helper log /var/log/apache2/access.log --format txt

# Email analysis with VirusTotal
secops-helper eml suspicious.eml --vt

# URL threat analysis
secops-helper url "http://suspicious-site.com" --format txt

# YARA malware scanning
secops-helper yara scan /samples/ --rules ./yaraScanner/rules/ --recursive

# Certificate analysis
secops-helper cert https://example.com

# Deobfuscate malicious script
secops-helper deobfuscate malware.js --extract-iocs
```

### STIX 2.1 Export

Export IOCs in STIX 2.1 format for sharing threat intelligence:

```bash
# Basic STIX export
secops-helper ioc report.txt --format stix --output indicators.json

# Direct tool usage with STIX
python iocExtractor/extractor.py report.txt --format stix
```

STIX output includes:
- Identity object (creator)
- Indicator objects for all IOCs
- Proper STIX 2.1 patterns
- Valid timestamps and references
- Support for IPs, domains, URLs, emails, and file hashes

## Configuration

Create a `.env` file in the project root for API keys and cache configuration:

```env
# VirusTotal API (used by EML Parser, Hash Lookup, Domain/IP Intel)
VT_API_KEY=your_virustotal_api_key

# AbuseIPDB API (used by Domain/IP Intel)
ABUSEIPDB_KEY=your_abuseipdb_api_key

# Redis Cache (optional - falls back to in-memory if not available)
REDIS_URL=redis://localhost:6379/0
```

**Getting API Keys:**
- VirusTotal: Sign up at [https://www.virustotal.com/](https://www.virustotal.com/) (free tier: 4 requests/minute)
- AbuseIPDB: Sign up at [https://www.abuseipdb.com/](https://www.abuseipdb.com/) (free tier available)

### Redis Caching

SecOps Helper uses Redis for intelligent caching of threat intelligence lookups, significantly improving performance for repeated queries.

**Features:**
- **Automatic Caching**: Hash lookups and domain/IP intelligence results are automatically cached
- **24-hour TTL**: Cache entries expire after 24 hours to ensure fresh data
- **Namespace Isolation**: Different tools use separate cache namespaces (hash_lookup, domain_ip_intel)
- **Fallback Support**: If Redis is unavailable, tools fall back to in-memory caching
- **Cache Statistics**: Track hits, misses, and hit rates via API

**Benefits:**
- ⚡ **10-100x faster** repeated lookups (no API calls)
- 💰 **Reduced API costs** - fewer VirusTotal/AbuseIPDB queries
- 📊 **Hit rate tracking** - monitor cache effectiveness
- 🔄 **Shared cache** - All tools and web dashboard share the same cache

**Using Redis with Docker:**

```bash
# Redis is automatically started with Docker Compose
docker-compose up -d

# The web dashboard and CLI tools will use Redis automatically
```

**Cache Management API:**

```bash
# Get cache statistics
curl http://localhost:5000/api/cache/stats

# Clear specific namespace
curl -X POST http://localhost:5000/api/cache/clear \
  -H "Content-Type: application/json" \
  -d '{"namespace": "hash_lookup"}'

# Clear all cache
curl -X POST http://localhost:5000/api/cache/clear \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Cache Statistics Example:**

```json
{
  "overall": {
    "backend": "redis",
    "hits": 450,
    "misses": 125,
    "hit_rate": 78.26,
    "total_keys": 350
  },
  "namespaces": {
    "hash_lookup": {"hits": 300, "misses": 75, "sets": 75},
    "domain_ip_intel": {"hits": 150, "misses": 50, "sets": 50}
  }
}
```

## Installation

### Option 1: Central Control System (Recommended - NEW!)

The new central control system provides the easiest and most powerful way to use SecOps Helper:

```bash
# Clone the repository
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (optional)
cp .env.example .env
# Edit .env with your API keys

# Make the control script executable
chmod +x secops

# Launch interactive mode
./secops

# Or use directly from command line
./secops list                    # List all tools
./secops info hash               # Get tool info
./secops search malware          # Search tools
./secops hash <hash_value>       # Run a tool
```

**Why use the Central Control System?**
- 🎯 Interactive menu for easy navigation
- 🔍 Smart search to find the right tool
- 📚 Built-in documentation for all tools
- ⚡ Single command to access any tool
- 📊 Tools organized by category
- ✅ API key status checking

### Option 2: Package Installation

```bash
# Clone the repository
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper

# Install as package (includes secops-helper command)
pip install -e .

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

After installation, you can use the unified `secops-helper` command:

```bash
# Show help
secops-helper --help

# Use any tool via unified CLI
secops-helper ioc threat_report.txt --format stix
secops-helper hash --file hashes.txt
secops-helper intel 8.8.8.8
```

### Option 3: Direct Usage

```bash
# Clone the repository
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper

# Install dependencies
pip install -r requirements.txt

# Use tools directly
python iocExtractor/extractor.py report.txt
python hashLookup/lookup.py <hash>
```

### Option 4: Docker (Recommended for Isolated Execution)

Docker containers provide isolated, reproducible environments perfect for security tools.

**Prerequisites:**
- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose installed (included with Docker Desktop)

**Quick Start:**

```bash
# Clone the repository
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper

# Build the Docker image
docker build -t secops-helper .

# Run any tool (mount your data directory)
docker run --rm -v $(pwd)/data:/data secops-helper ioc /data/report.txt

# With API keys (using .env file)
docker run --rm --env-file .env -v $(pwd)/data:/data secops-helper eml /data/email.eml --vt
```

**Using Docker Compose:**

Docker Compose provides a more convenient way to run SecOps Helper with all services:

```bash
# Create data and output directories
mkdir -p data output

# Copy sample files to data directory
cp samples/* data/

# Run IOC extraction
docker-compose run --rm secops-helper ioc /data/report.txt --format stix --output /output/iocs.json

# Run hash lookup with output
docker-compose run --rm secops-helper hash --file /data/hashes.txt --format csv --output /output/results.csv

# Run email analysis with VirusTotal
docker-compose run --rm secops-helper eml /data/suspicious.eml --vt --output /output/email_report.json

# Run log analysis
docker-compose run --rm secops-helper log /data/access.log --format json --output /output/alerts.json

# Run PCAP analysis
docker-compose run --rm secops-helper pcap /data/capture.pcap --verbose

# Interactive shell for debugging
docker-compose run --rm --entrypoint /bin/bash secops-helper

# Stop all services
docker-compose down
```

**Docker Features:**

- **Isolated Environment**: Runs in a secure container separate from your host system
- **No Python Setup**: All dependencies pre-installed in the image
- **Persistent Cache**: Redis container for caching threat intelligence lookups
- **Volume Mounting**: Easy access to input files and output results
- **API Key Support**: Pass environment variables securely via `.env` file
- **Reproducible**: Same environment across all machines

**Directory Structure:**

```
secops-helper/
├── data/          # Mount point for input files (read-only)
├── output/        # Mount point for output files (read-write)
└── .env           # API keys (optional, mounted read-only)
```

**Environment Variables:**

The Docker container supports the same environment variables as the native installation:

```bash
# .env file
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
```

**Advanced Usage:**

```bash
# Build with specific tag
docker build -t secops-helper:2.0.0 .

# Run specific tool with all options
docker run --rm \
  --env-file .env \
  -v $(pwd)/data:/data:ro \
  -v $(pwd)/output:/output \
  secops-helper ioc /data/threat_report.txt \
    --format stix \
    --output /output/indicators.json \
    --verbose

# Use Redis cache service
docker-compose up -d redis
docker-compose run --rm secops-helper hash --file /data/hashes.txt

# View cache statistics
docker-compose exec redis redis-cli INFO stats

# Clean up everything including volumes
docker-compose down -v
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

### Phase 4 (Completed ✅)
- [x] Comprehensive test suite (158 tests, >75% coverage)
- [x] CI/CD pipeline (GitHub Actions, pre-commit hooks)
- [x] Unified CLI tool (`secops-helper` command)
- [x] STIX 2.1 export support
- [x] Package installation support (setup.py)
- [x] Docker container support (Dockerfile, docker-compose.yml)
- [x] Web dashboard interface (Flask-based UI with REST API)
- [x] Redis caching with intelligent TTL and namespace isolation

### Future Enhancements
- [ ] MISP integration for threat intelligence sharing
- [ ] Real-time log monitoring with WebSocket support
- [ ] Machine learning-based anomaly detection
- [ ] Advanced correlation engine
- [ ] User authentication and multi-tenancy
- [ ] Scheduled analysis and reporting
- [ ] Advanced visualization with charts and graphs

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Security

This tool is designed for security analysis. Always handle malicious samples in isolated environments. Never execute extracted attachments or suspicious code.