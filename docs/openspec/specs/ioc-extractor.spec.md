# IOC Extractor - Feature Specification

## Overview

**Feature Name:** IOC Extractor
**Module:** iocExtractor
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** High
**Target Release:** Phase 2

## Purpose

The IOC Extractor automatically extracts Indicators of Compromise (IOCs) from various text sources including incident reports, malware analysis notes, threat intelligence feeds, and log files. It identifies and extracts IP addresses, domains, URLs, file hashes, email addresses, CVEs, and other security artifacts, then exports them in multiple standardized formats.

## User Stories

### Primary Use Cases

1. **As a Threat Intel Analyst**, I want to extract all IOCs from a PDF threat report to quickly populate my threat intelligence platform
2. **As an Incident Responder**, I need to extract IP addresses and domains from incident notes to create firewall rules and blocklists
3. **As a SOC Analyst**, I want to parse multiple threat feeds and consolidate IOCs into a single CSV for import into my SIEM
4. **As a Malware Analyst**, I need to extract file hashes from analysis reports and check them against multiple threat intelligence sources
5. **As a Security Researcher**, I want to defang/refang URLs and domains for safe documentation and sharing

## Functional Requirements

### FR-1: Text Input Sources
- **Description**: Accept IOC extraction from multiple input formats
- **Supported Formats**:
  - Plain text files (.txt)
  - Markdown files (.md)
  - JSON files (.json)
  - CSV files (.csv)
  - PDF documents (.pdf)
  - HTML files (.html)
  - Standard input (stdin/pipe)
- **Multi-file**: Support batch processing of multiple files

### FR-2: IP Address Extraction
- **Description**: Extract and validate IP addresses
- **Patterns Supported**:
  - IPv4 addresses (standard and CIDR notation)
  - IPv6 addresses
  - Defanged IPs (e.g., `192[.]0[.]2[.]1`)
- **Validation**:
  - Valid IP format
  - Optional filtering of private/reserved ranges
  - Automatic refanging of defanged IPs
- **Output**: Deduplicated list with optional counts

### FR-3: Domain Extraction
- **Description**: Extract and validate domain names
- **Patterns Supported**:
  - FQDNs (Fully Qualified Domain Names)
  - Subdomains
  - Defanged domains (e.g., `example[.]com`)
  - Domains with ports (e.g., `example.com:8080`)
- **Validation**:
  - Valid domain format (TLD validation)
  - Optional whitelist for known-good domains
  - Automatic refanging
- **Output**: Deduplicated list with context

### FR-4: URL Extraction
- **Description**: Extract URLs from text
- **Protocols**:
  - HTTP/HTTPS
  - FTP
  - Other protocols (customizable)
- **Features**:
  - Defanged URL support (e.g., `hxxp://example[.]com`)
  - URL parameter extraction
  - Path extraction
  - Automatic refanging for analysis
- **Output**: Full URLs with optional decomposition

### FR-5: File Hash Extraction
- **Description**: Extract and identify file hashes
- **Hash Types**:
  - MD5 (32 hex chars)
  - SHA1 (40 hex chars)
  - SHA256 (64 hex chars)
  - SHA512 (128 hex chars)
- **Features**:
  - Automatic hash type identification
  - Format validation
  - Case normalization (lowercase)
- **Output**: Organized by hash type

### FR-6: Email Address Extraction
- **Description**: Extract email addresses
- **Patterns**:
  - Standard email format
  - Defanged emails (e.g., `user[@]example[.]com`)
- **Validation**: RFC 5322 compliant
- **Output**: Deduplicated list

### FR-7: CVE Extraction
- **Description**: Extract CVE identifiers
- **Pattern**: CVE-YYYY-NNNNN format
- **Validation**: Proper CVE format
- **Enhancement**: Optional CVE details lookup from NVD
- **Output**: List with optional severity/CVSS data

### FR-8: Registry Key Extraction
- **Description**: Extract Windows registry keys
- **Patterns**: HKEY_* paths
- **Output**: List of registry IOCs

### FR-9: File Path Extraction
- **Description**: Extract suspicious file paths
- **Patterns**:
  - Windows paths (C:\, \\, etc.)
  - Unix paths (/etc, /tmp, etc.)
  - UNC paths
- **Output**: List of file paths

### FR-10: Defanging/Refanging
- **Description**: Convert IOCs between safe (defanged) and active (refanged) forms
- **Modes**:
  - `--defang`: Convert active IOCs to defanged for safe sharing
  - `--refang`: Convert defanged IOCs to active for analysis
- **Patterns**:
  - `.` to `[.]`
  - `http` to `hxxp`
  - `@` to `[@]`

### FR-11: Output Formats
- **Description**: Export IOCs in multiple formats
- **Supported Formats**:
  - JSON (default)
  - CSV
  - Plain text (one per line)
  - STIX 2.1 (Structured Threat Information)
  - MISP (JSON format for MISP import)
  - Markdown table
- **Structure**: Organized by IOC type with metadata

### FR-12: Deduplication & Counting
- **Description**: Remove duplicates and track frequency
- **Features**:
  - Automatic deduplication per IOC type
  - Count occurrences of each IOC
  - Sort by frequency or alphabetically
- **Output**: Include count metadata

### FR-13: Context Extraction
- **Description**: Extract surrounding context for each IOC
- **Features**:
  - N characters before/after IOC
  - Line number where IOC was found
  - Optional: Full sentence/paragraph containing IOC
- **Use Case**: Provide context for analyst review

### FR-14: Filtering & Whitelisting
- **Description**: Filter out known-good IOCs
- **Features**:
  - Built-in whitelist (RFC 1918 IPs, localhost, etc.)
  - Custom whitelist file support
  - Regex-based filtering
  - Minimum frequency threshold
- **Configuration**: YAML/JSON whitelist file

### FR-15: Batch Processing
- **Description**: Process multiple files in one run
- **Features**:
  - Directory scanning
  - Recursive subdirectory processing
  - File pattern matching (glob)
  - Combined or per-file output
- **Performance**: Parallel processing for large batches

## Non-Functional Requirements

### NFR-1: Performance
- Process 1MB text file in under 2 seconds
- Handle files up to 100MB
- Parallel processing for batch operations
- Memory efficient (streaming for large files)

### NFR-2: Accuracy
- > 99% accuracy for standard IOC formats
- Minimal false positives (< 1%)
- Configurable strictness levels

### NFR-3: Usability
- Simple CLI interface with sensible defaults
- Verbose mode for debugging
- Clear error messages
- Progress indicators for batch processing

### NFR-4: Extensibility
- Plugin system for custom IOC patterns
- Configurable regex patterns via config file
- Easy to add new output formats

### NFR-5: Security
- No external network calls by default
- Safe handling of malicious content
- Input sanitization
- No code execution from extracted data

## Technical Design

### Architecture

```
┌──────────────┐
│  Input(s)    │
│ Files/Stdin  │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│  File Parser     │
│  (PDF/TXT/JSON)  │
└──────┬───────────┘
       │
       ▼
┌──────────────────────┐
│  IOC Extractors      │
├──────────────────────┤
│ - IP Extractor       │
│ - Domain Extractor   │
│ - URL Extractor      │
│ - Hash Extractor     │
│ - Email Extractor    │
│ - CVE Extractor      │
│ - Path Extractor     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Validation &        │
│  Deduplication       │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Filtering &         │
│  Whitelisting        │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Output Formatter    │
│  (JSON/CSV/STIX)     │
└──────┬───────────────┘
       │
       ▼
┌──────────────┐
│  Export      │
└──────────────┘
```

### Regex Patterns

#### IP Addresses
```python
IPV4 = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
IPV4_DEFANGED = r'\b(?:[0-9]{1,3}\[\.\]){3}[0-9]{1,3}\b'
IPV6 = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
```

#### Domains
```python
DOMAIN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
DOMAIN_DEFANGED = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\[\.\])+[a-z]{2,}\b'
```

#### Hashes
```python
MD5 = r'\b[a-fA-F0-9]{32}\b'
SHA1 = r'\b[a-fA-F0-9]{40}\b'
SHA256 = r'\b[a-fA-F0-9]{64}\b'
SHA512 = r'\b[a-fA-F0-9]{128}\b'
```

### Data Structures

```python
class IOCResult:
    ioc_type: str  # 'ip', 'domain', 'hash', etc.
    value: str
    count: int
    context: List[str]
    line_numbers: List[int]
    metadata: Dict[str, Any]

class ExtractionResult:
    ips: List[IOCResult]
    domains: List[IOCResult]
    urls: List[IOCResult]
    hashes: Dict[str, List[IOCResult]]  # organized by hash type
    emails: List[IOCResult]
    cves: List[IOCResult]
    file_paths: List[IOCResult]
    registry_keys: List[IOCResult]
    summary: Dict[str, int]
```

## Command-Line Interface

### Syntax

```bash
python iocExtractor/extractor.py [INPUT] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `input` | string/stdin | No | File(s) to process (defaults to stdin) |

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--input-dir` | `-d` | string | - | Process all files in directory |
| `--recursive` | `-r` | flag | False | Recursively process subdirectories |
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | `-f` | string | json | Output format (json/csv/txt/stix/misp/markdown) |
| `--types` | `-t` | string | all | IOC types to extract (comma-separated) |
| `--defang` | | flag | False | Defang IOCs in output |
| `--refang` | | flag | False | Refang defanged IOCs |
| `--whitelist` | `-w` | string | - | Path to whitelist file |
| `--no-private-ips` | | flag | False | Exclude private IP ranges |
| `--context` | `-c` | int | 0 | Characters of context around IOC |
| `--min-count` | | int | 1 | Minimum occurrence count |
| `--deduplicate` | | flag | True | Remove duplicates |
| `--sort-by` | | string | type | Sort by: type, count, alpha |
| `--verbose` | `-v` | flag | False | Verbose output |
| `--config` | | string | - | Path to config file |

### Examples

#### Basic Extraction
```bash
# Extract all IOCs from a file
python iocExtractor/extractor.py report.txt

# Extract from stdin
cat incident_notes.txt | python iocExtractor/extractor.py
```

#### Specific IOC Types
```bash
# Extract only IPs and domains
python iocExtractor/extractor.py report.txt --types ip,domain

# Extract only file hashes
python iocExtractor/extractor.py analysis.txt --types hash
```

#### Output Formats
```bash
# Export to CSV
python iocExtractor/extractor.py report.txt -f csv -o iocs.csv

# Export to STIX 2.1
python iocExtractor/extractor.py threat_feed.txt -f stix -o iocs.json

# Export to Markdown table
python iocExtractor/extractor.py report.txt -f markdown -o iocs.md
```

#### Batch Processing
```bash
# Process all .txt files in directory
python iocExtractor/extractor.py --input-dir ./reports/ -f csv -o all_iocs.csv

# Recursive processing
python iocExtractor/extractor.py -d ./threat_intel/ -r -o consolidated.json
```

#### Filtering
```bash
# Exclude private IPs
python iocExtractor/extractor.py logs.txt --no-private-ips

# Use custom whitelist
python iocExtractor/extractor.py report.txt -w whitelist.txt

# Only IOCs seen 3+ times
python iocExtractor/extractor.py data.txt --min-count 3
```

#### Defanging
```bash
# Defang IOCs for safe sharing
python iocExtractor/extractor.py report.txt --defang -o safe_report.txt

# Refang defanged IOCs for analysis
python iocExtractor/extractor.py defanged.txt --refang -o active_iocs.json
```

## Output Schema

### JSON Format

```json
{
  "metadata": {
    "source_files": ["report.txt"],
    "extraction_date": "2025-11-18T10:00:00Z",
    "ioc_extractor_version": "1.0.0",
    "total_iocs": 45
  },
  "summary": {
    "ips": 12,
    "domains": 8,
    "urls": 15,
    "hashes": 5,
    "emails": 3,
    "cves": 2
  },
  "iocs": {
    "ips": [
      {
        "value": "192.0.2.1",
        "type": "ipv4",
        "count": 3,
        "first_seen_line": 15,
        "context": ["Malicious traffic from 192.0.2.1 detected"]
      }
    ],
    "domains": [
      {
        "value": "malicious.example.com",
        "count": 2,
        "first_seen_line": 22,
        "context": ["C2 server at malicious.example.com"]
      }
    ],
    "urls": [
      {
        "value": "http://phishing.example.com/login",
        "protocol": "http",
        "domain": "phishing.example.com",
        "path": "/login",
        "count": 1,
        "first_seen_line": 30
      }
    ],
    "hashes": {
      "md5": [
        {
          "value": "5d41402abc4b2a76b9719d911017c592",
          "count": 1,
          "first_seen_line": 45
        }
      ],
      "sha256": [
        {
          "value": "2c26b46b68ffc68ff99b453c1d30413413422d706...",
          "count": 2,
          "first_seen_line": 50
        }
      ]
    },
    "emails": [
      {
        "value": "attacker@example.com",
        "count": 1,
        "first_seen_line": 60
      }
    ],
    "cves": [
      {
        "value": "CVE-2024-1234",
        "count": 1,
        "first_seen_line": 70
      }
    ]
  }
}
```

### CSV Format

```csv
IOC_Type,Value,Count,First_Seen_Line,Context
ip,192.0.2.1,3,15,"Malicious traffic from 192.0.2.1 detected"
domain,malicious.example.com,2,22,"C2 server at malicious.example.com"
url,http://phishing.example.com/login,1,30,""
md5,5d41402abc4b2a76b9719d911017c592,1,45,""
```

### STIX 2.1 Format

```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--<uuid>",
      "created": "2025-11-18T10:00:00.000Z",
      "modified": "2025-11-18T10:00:00.000Z",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2025-11-18T10:00:00.000Z"
    }
  ]
}
```

## Configuration File

### YAML Format (ioc-config.yaml)

```yaml
extraction:
  types:
    - ip
    - domain
    - url
    - hash
    - email
    - cve

  context_chars: 100
  deduplicate: true
  case_sensitive: false

filtering:
  exclude_private_ips: true
  exclude_reserved_ips: true
  min_count: 1

  whitelist:
    domains:
      - "example.com"
      - "*.microsoft.com"
    ips:
      - "10.0.0.0/8"
      - "192.168.0.0/16"

output:
  format: json
  sort_by: count
  include_context: true
  include_line_numbers: true

custom_patterns:
  bitcoin_address: '\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
  ethereum_address: '\b0x[a-fA-F0-9]{40}\b'
```

## Dependencies

### Required Libraries
```
PyPDF2>=3.0.0          # PDF parsing
validators>=0.20.0      # Domain/URL validation
tldextract>=5.0.0      # Domain parsing
stix2>=3.0.0           # STIX format export
python-magic>=0.4.27   # File type detection
PyYAML>=6.0            # Config file parsing
```

### Optional
```
pdfplumber>=0.10.0     # Enhanced PDF extraction
textract>=1.6.5        # Multi-format text extraction
```

## Testing

### Test Cases

1. **TC-1: IP Extraction**
   - Input: Text with various IP formats
   - Expected: All IPs extracted and validated

2. **TC-2: Defanged IOC Extraction**
   - Input: Text with defanged IPs, domains, URLs
   - Expected: IOCs refanged correctly

3. **TC-3: Hash Identification**
   - Input: Mixed hash types (MD5, SHA1, SHA256)
   - Expected: Correct hash type identification

4. **TC-4: Batch Processing**
   - Input: Directory with 100 text files
   - Expected: All files processed, consolidated output

5. **TC-5: Whitelist Filtering**
   - Input: Text with private IPs and public IPs
   - Expected: Private IPs excluded when flag set

6. **TC-6: STIX Export**
   - Input: IOCs extracted from text
   - Expected: Valid STIX 2.1 JSON

7. **TC-7: PDF Processing**
   - Input: PDF threat report
   - Expected: IOCs extracted from PDF text

8. **TC-8: Deduplication**
   - Input: Text with repeated IOCs
   - Expected: Each IOC listed once with count

## Future Enhancements

1. **Machine Learning IOC Detection**
   - Train model to identify uncommon IOC patterns
   - Detect obfuscated IOCs

2. **Threat Intelligence Enrichment**
   - Auto-lookup IOCs against VirusTotal, AbuseIPDB
   - Add threat scores to output

3. **Relationship Mapping**
   - Identify relationships between IOCs
   - Generate graph visualization

4. **Live Feed Processing**
   - Monitor RSS/Atom threat feeds
   - Real-time IOC extraction

5. **API Server Mode**
   - RESTful API for IOC extraction
   - Webhook support

6. **Browser Extension**
   - Extract IOCs from web pages
   - One-click extraction and export

## Known Limitations

1. **OCR**: Does not extract text from images in PDFs
2. **Obfuscation**: Limited detection of heavily obfuscated IOCs
3. **Context**: Context extraction may miss multi-line references
4. **Performance**: Very large files (>1GB) may require streaming mode

## Security Considerations

- No automatic network lookups (prevents data leakage)
- Safe handling of malicious URLs (no auto-loading)
- Input sanitization to prevent injection attacks
- Sandboxed PDF parsing

## References

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/)
- [MISP Format](https://www.misp-project.org/)
- [OpenIOC Format](https://www.fireeye.com/blog/threat-research/2013/10/openioc-basics.html)
- [CybOX](https://cyboxproject.github.io/)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
