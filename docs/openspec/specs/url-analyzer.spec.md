# URL Analyzer - Feature Specification

## Overview

**Feature Name:** URL Analyzer
**Module:** urlAnalyzer
**Status:** Implemented
**Version:** 1.0.0
**Priority:** High
**Target Release:** Phase 3

## Purpose

The URL Analyzer provides comprehensive threat analysis for URLs using multiple detection methods including pattern-based detection, VirusTotal integration, and URLhaus database lookups. It identifies malicious, suspicious, and phishing URLs through advanced heuristics and threat intelligence correlation, supporting batch processing with intelligent caching.

## User Stories

### Primary Use Cases

1. **As a SOC Analyst**, I want to quickly check suspicious URLs from phishing emails against threat intelligence databases
2. **As an Incident Responder**, I need to analyze a list of URLs found in malware traffic to identify C2 servers
3. **As a Security Researcher**, I want to detect phishing URLs using pattern analysis even before they appear in threat feeds
4. **As a Threat Hunter**, I need to batch analyze URLs from proxy logs and identify high-risk destinations
5. **As an Email Security Admin**, I want to validate links before allowing them through the email gateway

## Functional Requirements

### FR-1: URL Validation & Normalization
- **Description**: Validate and normalize URLs for consistent analysis
- **Features**:
  - Regex-based URL validation (HTTP/HTTPS schemes)
  - Automatic scheme addition (default: http://)
  - Domain normalization (lowercase)
  - Path, query, and fragment preservation
  - Support for IP-based URLs
  - Support for localhost and standard domains
- **Validation Rules**:
  - Valid scheme (http:// or https://)
  - Valid domain or IP address
  - Optional port number
  - Valid path and query parameters

### FR-2: URL Parsing & Decomposition
- **Description**: Parse URLs into analyzable components
- **Extracted Components**:
  - Scheme (http/https)
  - Domain (normalized to lowercase)
  - Port number (if specified)
  - Path, parameters, query, fragment
  - Query parameters (parsed as key-value pairs)
  - File extension (from path)
  - Base domain (TLD + domain)
- **Use Case**: Enable granular analysis of URL components

### FR-3: Suspicious Pattern Detection
- **Description**: Detect malicious patterns using heuristics
- **Detection Categories** (11 checks):
  1. **IP Address URLs** - Uses IP instead of domain name (+20 risk)
  2. **Suspicious Keywords** - login, verify, paypal, etc. (+5 per keyword)
  3. **Dangerous Extensions** - .exe, .scr, .bat, .apk (+15 risk)
  4. **URL Encoding Obfuscation** - High % of encoded chars (+10 risk)
  5. **Free/Suspicious TLDs** - .tk, .ml, .ga, .cf, .gq (+15 risk)
  6. **Excessive Subdomains** - More than 3 levels (+10 risk)
  7. **Long Domains** - Over 50 characters (+10 risk)
  8. **Homograph Attacks** - Non-ASCII characters (+20 risk)
- **Risk Scoring**: 0-100 scale, suspicious threshold: 30
- **Keywords List**: 14 phishing-related terms (banking, suspended, verify, etc.)
- **Extensions List**: 13 executable file types

### FR-4: VirusTotal Integration
- **Description**: Query VirusTotal API v3 for URL reputation
- **API Features**:
  - URL ID encoding (base64 urlsafe)
  - GET request to `/api/v3/urls/{url_id}`
  - API key via x-apikey header
  - Timeout: 15 seconds
- **Extracted Data**:
  - Detection statistics (malicious, suspicious, harmless, undetected)
  - Total analysis votes
  - URL categories
  - Last analysis date
  - Permalink to VT GUI
- **Verdict Classification**:
  - Malicious: ≥3 malicious detections
  - Suspicious: 1-2 malicious or ≥2 suspicious
  - Clean: Harmless detections, no malicious
  - Unknown: Not in VT database (404 response)
- **Error Handling**: Graceful fallback on API errors

### FR-5: URLhaus Database Lookup
- **Description**: Query URLhaus (abuse.ch) for known malicious URLs
- **API Integration**:
  - POST to `https://urlhaus-api.abuse.ch/v1/url/`
  - No API key required (public database)
  - Timeout: 15 seconds
- **Response Data**:
  - Verdict (malicious if found)
  - Threat type (malware family)
  - Tags (attack categories)
  - Date added to database
  - URL status (online/offline)
  - Reporter information
  - Permalink to URLhaus
- **Coverage**: Known malware distribution URLs, phishing sites, C2 servers

### FR-6: Multi-Source Verdict Correlation
- **Description**: Aggregate results from all sources into final verdict
- **Verdict Logic** (priority order):
  1. URLhaus = malicious → **MALICIOUS** (highest confidence)
  2. VirusTotal = malicious → **MALICIOUS**
  3. VirusTotal = suspicious → **SUSPICIOUS**
  4. Pattern analysis suspicious → **SUSPICIOUS**
  5. VirusTotal = clean → **CLEAN**
  6. Otherwise → **UNKNOWN**
- **Risk Classification**:
  - **High**: Malicious verdict
  - **Medium**: Suspicious verdict OR pattern score >50
  - **Low**: Clean verdict
  - **Unknown**: No data available

### FR-7: Intelligent Caching
- **Description**: Cache analysis results to minimize API calls
- **Cache Backend**: Redis (primary) or in-memory (fallback)
- **Cache Strategy**:
  - Namespace: `url_analysis`
  - TTL: 86400 seconds (24 hours)
  - Cache key: Normalized URL
  - Cache before API calls (check first)
  - Cache after analysis (store results)
- **Cache Metadata**: Results marked as `cached: true/false`
- **Performance**: Cached lookups <100ms, uncached 2-5s

### FR-8: Batch Processing
- **Description**: Analyze multiple URLs efficiently
- **Input Methods**:
  - Command-line argument (single URL)
  - File input (one URL per line)
  - Combination of both
- **Processing**:
  - Sequential analysis with progress tracking
  - Verbose mode shows progress (N/Total)
  - Cache hits accelerate batch processing
- **Progress Indicators**: `[1/100] Analyzing http://...` (verbose mode)

### FR-9: Multiple Output Formats
- **Description**: Export results in various formats
- **Supported Formats**:
  1. **JSON** (default) - Full structured data with metadata
  2. **CSV** - Tabular format (URL, Verdict, Risk, VT Malicious, URLhaus, Suspicions)
  3. **Text** - Human-readable report with sections
- **JSON Structure**:
  - metadata (analysis date, total URLs, tool version)
  - results array (per-URL analysis)
  - Each result includes: parsed components, pattern analysis, threat intelligence, verdict
- **CSV Columns**: URL, Verdict, Risk Level, VT Malicious Count, URLhaus Status, Suspicion Count
- **Text Format**: 80-character dividers, hierarchical sections, readable layout

### FR-10: URL Defanging
- **Description**: Convert URLs to safe sharing format
- **Defanging Rules**:
  - `http://` → `hxxp://`
  - `https://` → `hxxps://`
  - `.` → `[.]`
- **Use Case**: Share IOCs without accidental clicks
- **Example**: `https://evil.com/path` → `hxxps://evil[.]com/path`

### FR-11: Verbose & Debug Output
- **Description**: Detailed logging for troubleshooting
- **Verbose Mode** (`--verbose`):
  - Cache hit/miss notifications
  - Analysis progress per URL
  - Truncated URL display (50 chars)
  - Stderr output (doesn't pollute results)
- **Information Logged**:
  - `[Cache hit] https://example.com`
  - `[Analyzing] https://example.com`
  - `[1/10] Analyzing http://...`

### FR-12: API Key Management
- **Description**: Secure handling of API credentials
- **Configuration**: Environment variables via `.env`
- **Required Keys**:
  - `VT_API_KEY` - VirusTotal API key (optional)
- **Graceful Degradation**:
  - If VT key missing: Skip VT analysis, use URLhaus + patterns only
  - No hard failures on missing keys
- **Security**: Never log or expose API keys

### FR-13: Error Handling
- **Description**: Robust error management
- **Error Types**:
  - Invalid URL format → Return error in result object
  - File not found → Exit with error message
  - API failures → Mark source as error, continue analysis
  - Network timeouts → 15-second timeout, return error
- **Partial Results**: Continue processing batch even if individual URLs fail
- **Error Messages**: Clear, actionable (e.g., "File not found: urls.txt")

### FR-14: Result Metadata
- **Description**: Comprehensive analysis metadata
- **Metadata Fields**:
  - Tool name and version
  - Analysis timestamp (ISO 8601 UTC)
  - Total URLs analyzed
  - Original URL (as provided)
  - Normalized URL (processed)
  - Cached status (boolean)
- **Per-URL Metadata**: Analysis date, cache status, original vs normalized URL

### FR-15: File Output Support
- **Description**: Save results to files
- **Output Options**:
  - `--output <file>` - Write to specified file
  - Default: stdout
- **File Writing**:
  - Format determined by `--format` flag
  - Success message to stderr
  - Automatic file creation/overwriting
- **Use Case**: Integrate with other tools, preserve analysis results

## Non-Functional Requirements

### NFR-1: Performance
- Single URL analysis (cached): < 100ms
- Single URL analysis (API): 2-5 seconds
- Batch 100 URLs (all cached): < 10 seconds
- Batch 100 URLs (no cache): ~8-10 minutes (API rate limits)
- Pattern detection: < 50ms per URL

### NFR-2: Reliability
- Handle API failures gracefully (continue analysis)
- Network timeout protection (15s)
- Cache fallback (Redis → in-memory)
- No crashes on malformed URLs
- Partial results on batch processing errors

### NFR-3: Accuracy
- Pattern detection: <5% false positive rate
- Verdict correlation: Prioritize high-confidence sources
- URL normalization: No data loss
- Homograph detection: Basic non-ASCII check

### NFR-4: Usability
- Simple CLI with sensible defaults
- Clear error messages
- Help documentation with examples
- Minimal required arguments (just URL)
- Verbose mode for transparency

### NFR-5: Security
- HTTPS for all API calls
- Secure API key storage (environment variables)
- No logging of API keys
- Input validation (prevent injection)
- URL defanging capability

## Technical Design

### Architecture

```
┌─────────────────┐
│  Input Handler  │
│  (CLI/File)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  URL Validator  │
│  & Normalizer   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────┐
│  Cache Manager  │◄────►│ Redis Cache  │
│  (24h TTL)      │      │  (fallback)  │
└────────┬────────┘      └──────────────┘
         │
         ▼
┌─────────────────┐
│   URL Parser    │
│  (decompose)    │
└────────┬────────┘
         │
    ┌────┴─────────────┬──────────────┐
    │                  │              │
    ▼                  ▼              ▼
┌───────────┐   ┌──────────┐   ┌─────────────┐
│ Pattern   │   │ URLhaus  │   │ VirusTotal  │
│ Detection │   │ API      │   │ API (v3)    │
└─────┬─────┘   └─────┬────┘   └──────┬──────┘
      │               │               │
      └───────────────┴───────────────┘
                      │
                      ▼
              ┌───────────────┐
              │    Verdict    │
              │  Aggregator   │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │    Output     │
              │  Formatter    │
              │ (JSON/CSV/TXT)│
              └───────────────┘
```

### Core Components

#### URLValidator
```python
class URLValidator:
    URL_PATTERN = re.compile(r'^https?://...')  # Full regex

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid"""

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for consistent analysis"""

    @staticmethod
    def defang_url(url: str) -> str:
        """Defang URL for safe sharing"""
```

#### URLParser
```python
class URLParser:
    @staticmethod
    def parse_url(url: str) -> Dict:
        """Parse URL into components
        Returns: {
            'original', 'scheme', 'domain', 'port',
            'path', 'query', 'query_params',
            'file_extension', 'base_domain'
        }
        """
```

#### SuspiciousPatternDetector
```python
class SuspiciousPatternDetector:
    SUSPICIOUS_KEYWORDS = [14 phishing terms]
    SUSPICIOUS_EXTENSIONS = [13 executable types]
    SUSPICIOUS_PATTERNS = [4 regex patterns]

    @staticmethod
    def analyze_url(url: str, parsed: Dict) -> Dict:
        """Detect suspicious patterns
        Returns: {
            'suspicions': List[str],
            'risk_score': int (0-100),
            'is_suspicious': bool (score > 30)
        }
        """
```

#### VirusTotalURLAPI
```python
class VirusTotalURLAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'

    def analyze_url(self, url: str) -> Optional[Dict]:
        """Query VT API v3
        Returns: {
            'source': 'virustotal',
            'malicious', 'suspicious', 'harmless', 'undetected',
            'total_votes', 'verdict', 'categories',
            'last_analysis_date', 'permalink'
        }
        """

    def _classify_verdict(self, stats: Dict) -> str:
        """malicious/suspicious/clean/unknown"""
```

#### URLhausAPI
```python
class URLhausAPI:
    def __init__(self):
        self.base_url = 'https://urlhaus-api.abuse.ch/v1'

    def lookup_url(self, url: str) -> Optional[Dict]:
        """Query URLhaus database
        Returns: {
            'source': 'urlhaus',
            'verdict': 'malicious'/'unknown',
            'threat', 'tags', 'date_added',
            'url_status', 'reporter', 'permalink'
        }
        """
```

#### URLAnalyzer (Main Orchestrator)
```python
class URLAnalyzer:
    CACHE_NAMESPACE = 'url_analysis'
    CACHE_TTL = 86400  # 24 hours

    def __init__(self, cache_enabled=True, verbose=False):
        """Initialize with cache and APIs"""

    def analyze(self, url: str) -> Dict:
        """Comprehensive URL analysis
        1. Normalize & validate
        2. Check cache
        3. Parse URL
        4. Pattern detection
        5. Query URLhaus
        6. Query VirusTotal
        7. Calculate verdict
        8. Cache result
        """

    def analyze_batch(self, urls: List[str]) -> List[Dict]:
        """Batch analysis with progress tracking"""

    def _calculate_verdict(self, result: Dict) -> str:
        """Aggregate multi-source verdict"""

    def _classify_risk(self, result: Dict) -> str:
        """high/medium/low/unknown"""
```

### Data Structures

```python
# Analysis Result
{
    'url': str,                    # Normalized URL
    'original_url': str,           # As provided
    'analysis_date': str,          # ISO 8601 UTC
    'parsed': {
        'scheme': str,
        'domain': str,
        'port': int,
        'path': str,
        'query_params': Dict,
        'file_extension': str,
        'base_domain': str
    },
    'pattern_analysis': {
        'suspicions': List[str],   # Human-readable findings
        'risk_score': int,         # 0-100
        'is_suspicious': bool
    },
    'threat_intelligence': {
        'urlhaus': {
            'verdict': str,
            'threat': str,
            'tags': List[str],
            'date_added': str,
            'url_status': str,
            'reporter': str,
            'permalink': str
        },
        'virustotal': {
            'malicious': int,
            'suspicious': int,
            'harmless': int,
            'undetected': int,
            'total_votes': int,
            'verdict': str,
            'categories': Dict,
            'last_analysis_date': int,
            'permalink': str
        }
    },
    'verdict': str,                # malicious/suspicious/clean/unknown
    'risk_level': str,             # high/medium/low/unknown
    'cached': bool
}
```

## Command-Line Interface

### Syntax

```bash
python urlAnalyzer/analyzer.py [URL] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `url` | string | No* | URL to analyze |

*Required if `--file` not specified

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--file` | `-f` | string | - | File with URLs (one per line) |
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | | string | json | Output format (json/csv/txt) |
| `--no-cache` | | flag | False | Disable caching |
| `--verbose` | `-v` | flag | False | Verbose output to stderr |

### Examples

#### Single URL Analysis
```bash
# Analyze single URL
python urlAnalyzer/analyzer.py "http://suspicious-site.com"

# With verbose mode
python urlAnalyzer/analyzer.py "https://example.com" --verbose
```

#### Batch Analysis
```bash
# From file (one URL per line)
python urlAnalyzer/analyzer.py --file urls.txt

# Multiple sources
python urlAnalyzer/analyzer.py "http://test.com" --file additional_urls.txt
```

#### Output Formats
```bash
# JSON output (default)
python urlAnalyzer/analyzer.py -f urls.txt

# CSV export
python urlAnalyzer/analyzer.py -f urls.txt --format csv -o results.csv

# Text report
python urlAnalyzer/analyzer.py -f urls.txt --format txt -o report.txt
```

#### Caching Control
```bash
# Disable cache (always query APIs)
python urlAnalyzer/analyzer.py "http://example.com" --no-cache

# Default: cache enabled (24h TTL)
python urlAnalyzer/analyzer.py "http://example.com"
```

#### Integration Examples
```bash
# Pipeline with IOC extractor
python iocExtractor/extractor.py email.eml | \
  jq -r '.results.urls[]' | \
  python urlAnalyzer/analyzer.py --file -

# Analyze only malicious URLs
python urlAnalyzer/analyzer.py -f urls.txt --format csv | \
  awk -F, '$2 == "malicious"'
```

## Output Schema

### JSON Format

```json
{
  "metadata": {
    "analysis_date": "2025-11-18T10:00:00Z",
    "total_urls": 3,
    "tool": "url_analyzer",
    "version": "1.0.0"
  },
  "results": [
    {
      "url": "http://malicious-site.com/payload.exe",
      "original_url": "malicious-site.com/payload.exe",
      "analysis_date": "2025-11-18T10:00:00Z",
      "parsed": {
        "scheme": "http",
        "domain": "malicious-site.com",
        "port": null,
        "path": "/payload.exe",
        "query": "",
        "query_params": {},
        "file_extension": "exe",
        "base_domain": "malicious-site.com"
      },
      "pattern_analysis": {
        "suspicions": [
          "Suspicious file extension: .exe"
        ],
        "risk_score": 15,
        "is_suspicious": false
      },
      "threat_intelligence": {
        "urlhaus": {
          "source": "urlhaus",
          "verdict": "malicious",
          "threat": "malware_download",
          "tags": ["exe", "TrickBot"],
          "date_added": "2025-11-10",
          "url_status": "online",
          "reporter": "abuse_ch",
          "permalink": "https://urlhaus.abuse.ch/url/12345/"
        },
        "virustotal": {
          "source": "virustotal",
          "malicious": 12,
          "suspicious": 3,
          "harmless": 45,
          "undetected": 10,
          "total_votes": 70,
          "verdict": "malicious",
          "categories": {"malware": true},
          "last_analysis_date": 1700000000,
          "permalink": "https://www.virustotal.com/gui/url/..."
        }
      },
      "verdict": "malicious",
      "risk_level": "high",
      "cached": false
    },
    {
      "url": "https://legitimate-site.com",
      "original_url": "https://legitimate-site.com",
      "analysis_date": "2025-11-18T10:00:01Z",
      "parsed": {
        "scheme": "https",
        "domain": "legitimate-site.com",
        "port": null,
        "path": "",
        "file_extension": null,
        "base_domain": "legitimate-site.com"
      },
      "pattern_analysis": {
        "suspicions": [],
        "risk_score": 0,
        "is_suspicious": false
      },
      "threat_intelligence": {
        "urlhaus": {
          "source": "urlhaus",
          "verdict": "unknown",
          "note": "URL not found in URLhaus database"
        },
        "virustotal": {
          "source": "virustotal",
          "malicious": 0,
          "suspicious": 0,
          "harmless": 65,
          "undetected": 5,
          "total_votes": 70,
          "verdict": "clean",
          "permalink": "https://www.virustotal.com/gui/url/..."
        }
      },
      "verdict": "clean",
      "risk_level": "low",
      "cached": true
    }
  ]
}
```

### CSV Format

```csv
URL,Verdict,Risk Level,VT Malicious,URLhaus Status,Suspicions
"http://malicious-site.com/payload.exe",malicious,high,12,malicious,1
"https://legitimate-site.com",clean,low,0,unknown,0
```

### Text Format

```
================================================================================
URL: http://malicious-site.com/payload.exe
Verdict: MALICIOUS
Risk Level: HIGH

Suspicious Patterns (15/100):
  - Suspicious file extension: .exe

VirusTotal:
  Malicious: 12
  Suspicious: 3
  Verdict: malicious

URLhaus: MALICIOUS
  Threat: malware_download
  Tags: exe, TrickBot

================================================================================
```

## Dependencies

### Required Libraries
```
requests>=2.31.0
python-dotenv>=1.0.0
redis>=5.0.0           # For caching
```

### Optional
```
stix2>=3.0.0           # Future STIX export
```

## API Integrations

### VirusTotal API v3
```python
GET https://www.virustotal.com/api/v3/urls/{url_id}
Headers: x-apikey: YOUR_VT_API_KEY
URL ID: base64_urlsafe_encode(url) without padding
```

**Rate Limits:** Free tier: 4 requests/minute

### URLhaus API
```python
POST https://urlhaus-api.abuse.ch/v1/url/
Data: {'url': 'http://example.com'}
```

**Rate Limits:** No authentication required, reasonable use expected

## Testing

### Test Cases

1. **TC-1: Valid HTTP URL**
   - Input: `http://example.com`
   - Expected: Normalized, parsed, analyzed

2. **TC-2: HTTPS URL with Path**
   - Input: `https://example.com/path/file.exe`
   - Expected: Extension detected, risk score >0

3. **TC-3: URL Without Scheme**
   - Input: `example.com`
   - Expected: Auto-add http://, process normally

4. **TC-4: Malicious URL (URLhaus)**
   - Input: Known malicious URL
   - Expected: URLhaus verdict = malicious

5. **TC-5: Phishing Patterns**
   - Input: `http://paypal-verify.tk/login`
   - Expected: High risk score (keywords + free TLD)

6. **TC-6: Cache Hit**
   - Input: Previously analyzed URL
   - Expected: Instant response, cached=true

7. **TC-7: Batch Processing**
   - Input: File with 10 URLs
   - Expected: All analyzed, progress shown (verbose)

8. **TC-8: Invalid URL**
   - Input: `not-a-url`
   - Expected: Error in result object

9. **TC-9: IP-Based URL**
   - Input: `http://192.168.1.1/malware.exe`
   - Expected: Risk score +20 for IP + +15 for .exe

10. **TC-10: No API Key**
    - Input: URL with VT_API_KEY unset
    - Expected: Skip VT, use URLhaus + patterns

## Future Enhancements

1. **Screenshot Capture**
   - Take screenshots of suspicious URLs
   - Visual phishing detection

2. **Redirect Chain Analysis**
   - Follow URL redirects
   - Detect redirect-based phishing

3. **Machine Learning Classification**
   - Train ML model on URL features
   - Improve pattern detection accuracy

4. **WHOIS Integration**
   - Domain registration date
   - Registrar information
   - Newly registered domain detection

5. **SSL Certificate Analysis**
   - Check certificate validity
   - Detect self-signed certificates
   - Certificate mismatch detection

6. **Typosquatting Detection**
   - Levenshtein distance from known brands
   - Homoglyph detection (advanced)

7. **Real-time Submission**
   - Submit unknown URLs to VT for scanning
   - Monitor analysis results

8. **Integration with OpenPhish**
   - Additional phishing database
   - Cross-reference findings

## Known Limitations

- VirusTotal free tier: 4 requests/minute (slow for large batches)
- URLhaus limited to known malicious URLs (no clean verdicts)
- Pattern detection has false positives (legitimate sites with keywords)
- Homograph detection basic (only non-ASCII check)
- No redirect following (analyzes only provided URL)
- No screenshot/visual analysis

## Security Considerations

- API keys stored in `.env`, never in code
- HTTPS for all API communications
- No execution of URLs (analysis only)
- Input validation prevents injection
- Defanging available for safe sharing
- No sensitive data logged

## Performance Metrics

- Single lookup (cached): < 100ms
- Single lookup (API): 2-5 seconds
- Pattern detection: < 50ms
- Batch 100 URLs (cached): < 10 seconds
- Batch 100 URLs (uncached): 8-10 minutes (VT rate limits)

## References

- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference/overview)
- [URLhaus API Documentation](https://urlhaus.abuse.ch/api/)
- [URL Parsing (RFC 3986)](https://www.rfc-editor.org/rfc/rfc3986)
- [Phishing Detection Patterns](https://www.phishtank.com/)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-20
**Next Review:** 2026-02-20
