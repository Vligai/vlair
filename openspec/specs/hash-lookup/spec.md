# Hash Lookup - Feature Specification

## Overview

**Feature Name:** Hash Lookup
**Module:** hashLookup
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** High
**Target Release:** Phase 2

## Purpose

The Hash Lookup utility performs bulk file hash queries against multiple threat intelligence sources to identify known malicious files. It supports batch processing of hashes, caching results, and exporting comprehensive threat reports with verdicts from VirusTotal, MalwareBazaar, and other threat intelligence platforms.

## User Stories

### Primary Use Cases

1. **As a Malware Analyst**, I want to check a list of 100 file hashes against threat intelligence databases to identify which files are malicious
2. **As an Incident Responder**, I need to quickly validate if files found on a compromised system are known malware
3. **As a Threat Hunter**, I want to batch check hashes from endpoint logs and generate a report of all malicious detections
4. **As a SOC Analyst**, I need to lookup file hashes with rate limiting to stay within free API quotas
5. **As a Security Researcher**, I want to maintain a local cache of hash lookups to avoid redundant API calls

## Functional Requirements

### FR-1: Multi-Source Hash Lookup
- **Description**: Query multiple threat intelligence sources
- **Supported Sources**:
  - VirusTotal (primary)
  - MalwareBazaar
  - ThreatFox
  - Hybrid Analysis
  - Local database (optional)
- **Aggregation**: Combine results from all sources
- **Priority**: Configurable source priority

### FR-2: Hash Type Support
- **Description**: Support all common hash algorithms
- **Supported Types**:
  - MD5 (32 hex characters)
  - SHA1 (40 hex characters)
  - SHA256 (64 hex characters)
  - SHA512 (128 hex characters)
- **Auto-Detection**: Automatically identify hash type by length
- **Validation**: Verify valid hexadecimal format

### FR-3: Batch Processing
- **Description**: Process multiple hashes efficiently
- **Input Methods**:
  - Command-line arguments (space/comma separated)
  - Input file (one hash per line)
  - CSV file with hash column
  - Standard input (pipe)
- **Performance**: Parallel processing with configurable workers
- **Progress**: Progress bar for large batches

### FR-4: Rate Limiting
- **Description**: Respect API rate limits for each source
- **Features**:
  - Configurable requests per minute
  - Automatic throttling
  - Queue management
  - Retry logic with exponential backoff
- **Profiles**: Pre-configured profiles (free, premium)

### FR-5: Result Caching
- **Description**: Cache lookup results to minimize API calls
- **Storage**:
  - SQLite database (default)
  - JSON file (alternative)
  - Redis (optional, for shared cache)
- **Cache Management**:
  - Configurable TTL (time-to-live)
  - Cache invalidation
  - Cache statistics
- **Efficiency**: Check cache before API calls

### FR-6: Threat Intelligence Enrichment
- **Description**: Extract detailed threat information
- **Data Points**:
  - Malware family/name
  - First/last seen dates
  - File type and size
  - Detection ratio (X/Y engines)
  - Threat categories/tags
  - YARA rule matches
  - Behavioral indicators
- **VirusTotal Specific**:
  - AV verdicts by engine
  - Crowdsourced IDS rules
  - Submission names
  - Community votes

### FR-7: Verdict Classification
- **Description**: Classify hashes by threat level
- **Categories**:
  - **Malicious**: Confirmed malware (detection > threshold)
  - **Suspicious**: Some detections (1-threshold)
  - **Clean**: No detections from any source
  - **Unknown**: Not found in any database
- **Threshold**: Configurable detection ratio for classification
- **Consensus**: Multi-source voting

### FR-8: Output Formats
- **Description**: Export results in multiple formats
- **Supported Formats**:
  - JSON (detailed, includes all metadata)
  - CSV (tabular, for spreadsheets)
  - Plain text (summary only)
  - HTML (interactive report)
  - Markdown (documentation)
  - STIX 2.1 (threat intelligence sharing)
- **Templates**: Customizable output templates

### FR-9: Filtering & Sorting
- **Description**: Filter and organize results
- **Filters**:
  - Show only malicious/suspicious/clean
  - Minimum detection count
  - Specific malware families
  - Date ranges
- **Sorting**:
  - By detection ratio (descending)
  - By hash type
  - Alphabetically
  - By first seen date

### FR-10: Export to Blocklists
- **Description**: Generate blocklists from malicious hashes
- **Formats**:
  - Plain text (one per line)
  - CSV with metadata
  - YARA rules (hash-based)
  - EDR/AV import formats
- **Filtering**: Only confirmed malicious hashes

### FR-11: Differential Analysis
- **Description**: Compare hash lists over time
- **Features**:
  - Compare two hash lists
  - Identify new/removed hashes
  - Track verdict changes
  - Generate change report
- **Use Case**: Monitor for newly identified threats

### FR-12: Local Hash Database
- **Description**: Maintain local database of known hashes
- **Features**:
  - Import custom hash lists
  - Tag hashes (internal tracking)
  - Notes/comments per hash
  - First/last seen tracking
- **Integration**: Query local DB before external APIs

### FR-13: Submission Capability
- **Description**: Submit unknown hashes for analysis
- **Platforms**:
  - VirusTotal (if file available)
  - MalwareBazaar (manual submission)
- **Workflow**: Flag unknowns for manual review/submission

### FR-14: API Key Management
- **Description**: Secure management of API keys
- **Storage**: Environment variables (.env file)
- **Validation**: Check API key validity on startup
- **Fallback**: Graceful degradation if keys unavailable

### FR-15: Verbose & Debug Modes
- **Description**: Detailed logging for troubleshooting
- **Levels**:
  - Normal: Summary only
  - Verbose: Progress and API calls
  - Debug: Full request/response logging
- **Output**: Console and optional log file

## Non-Functional Requirements

### NFR-1: Performance
- Lookup single hash in < 2 seconds
- Process 1000 hashes in < 10 minutes (with rate limiting)
- Cache lookups < 100ms
- Parallel processing (5-10 workers)

### NFR-2: Reliability
- Handle API failures gracefully
- Retry failed requests (3 attempts)
- Continue processing on individual failures
- Network timeout protection (30s)

### NFR-3: Accuracy
- No false positives in hash validation
- Accurate verdict classification
- Proper handling of edge cases (e.g., 0/0 detections)

### NFR-4: Usability
- Simple CLI with sensible defaults
- Clear progress indicators
- Informative error messages
- Help documentation with examples

### NFR-5: Security
- Secure API key storage
- No logging of API keys
- HTTPS for all API calls
- Input validation (prevent injection)

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
│  Hash Validator │
│  & Parser       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────┐
│  Cache Manager  │◄────►│ SQLite Cache │
└────────┬────────┘      └──────────────┘
         │
         ▼
┌─────────────────────────┐
│  Query Orchestrator     │
│  (Rate Limiting, Queue) │
└────────┬────────────────┘
         │
         ├──────┬──────┬──────┬──────┐
         ▼      ▼      ▼      ▼      ▼
    ┌────────────────────────────┐
    │    API Connectors          │
    ├────────────────────────────┤
    │ - VirusTotal               │
    │ - MalwareBazaar            │
    │ - ThreatFox                │
    │ - Hybrid Analysis          │
    │ - Local DB                 │
    └────────┬───────────────────┘
             │
             ▼
    ┌────────────────────┐
    │  Result Aggregator │
    │  & Classifier      │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  Output Formatter  │
    │  (JSON/CSV/HTML)   │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────┐
    │  Export        │
    └────────────────┘
```

### Core Components

#### HashValidator
```python
class HashValidator:
    def validate(self, hash_str: str) -> Tuple[bool, str]:
        """Validate hash and return (is_valid, hash_type)"""

    def normalize(self, hash_str: str) -> str:
        """Convert to lowercase, remove whitespace"""
```

#### CacheManager
```python
class CacheManager:
    def get(self, hash_value: str) -> Optional[Dict]:
        """Retrieve cached result"""

    def set(self, hash_value: str, result: Dict, ttl: int):
        """Store result with TTL"""

    def stats(self) -> Dict:
        """Return cache hit/miss statistics"""
```

#### RateLimiter
```python
class RateLimiter:
    def __init__(self, requests_per_minute: int):
        """Initialize with rate limit"""

    async def acquire(self):
        """Wait if necessary to respect rate limit"""
```

#### ThreatIntelSource (Abstract)
```python
class ThreatIntelSource(ABC):
    @abstractmethod
    async def lookup(self, hash_value: str, hash_type: str) -> Dict:
        """Query the threat intel source"""

    @abstractmethod
    def parse_response(self, response: Dict) -> ThreatResult:
        """Parse API response into standard format"""
```

### Data Structures

```python
@dataclass
class ThreatResult:
    hash_value: str
    hash_type: str
    verdict: str  # malicious, suspicious, clean, unknown
    detection_ratio: str  # "45/65"
    malware_family: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    file_type: Optional[str]
    file_size: Optional[int]
    sources: Dict[str, SourceResult]  # results per source
    metadata: Dict[str, Any]

@dataclass
class SourceResult:
    source_name: str
    verdict: str
    detections: int
    total_engines: int
    malware_names: List[str]
    tags: List[str]
    permalink: str
    raw_response: Dict
```

## Command-Line Interface

### Syntax

```bash
python hashLookup/lookup.py [HASHES] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `hashes` | string | No* | Space or comma-separated hashes |

*Required if `--file` not specified

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--file` | `-f` | string | - | File with hashes (one per line) |
| `--csv` | | string | - | CSV file with hash column |
| `--column` | | string | hash | CSV column name containing hashes |
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | | string | json | Output format (json/csv/txt/html/md/stix) |
| `--sources` | `-s` | string | all | Comma-separated sources to query |
| `--cache` | | flag | True | Use cache (disable with --no-cache) |
| `--cache-ttl` | | int | 86400 | Cache TTL in seconds (default 24h) |
| `--rate-limit` | `-r` | int | 4 | Requests per minute (VT free tier) |
| `--workers` | `-w` | int | 5 | Parallel worker threads |
| `--threshold` | `-t` | int | 5 | Min detections for "malicious" verdict |
| `--filter` | | string | all | Filter results (all/malicious/suspicious/clean/unknown) |
| `--verbose` | `-v` | flag | False | Verbose output |
| `--debug` | | flag | False | Debug logging |
| `--no-color` | | flag | False | Disable colored output |
| `--export-blocklist` | | string | - | Export malicious hashes to file |

### Examples

#### Single Hash Lookup
```bash
# Lookup single MD5 hash
python hashLookup/lookup.py 5d41402abc4b2a76b9719d911017c592

# Lookup SHA256
python hashLookup/lookup.py 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
```

#### Batch Lookup
```bash
# From command line (space-separated)
python hashLookup/lookup.py hash1 hash2 hash3

# From file (one per line)
python hashLookup/lookup.py --file hashes.txt

# From CSV
python hashLookup/lookup.py --csv incident_files.csv --column file_hash
```

#### Output Formats
```bash
# Export to CSV
python hashLookup/lookup.py -f hashes.txt --format csv -o results.csv

# Generate HTML report
python hashLookup/lookup.py -f hashes.txt --format html -o report.html

# Export to STIX
python hashLookup/lookup.py -f hashes.txt --format stix -o threats.json
```

#### Filtering
```bash
# Show only malicious hashes
python hashLookup/lookup.py -f hashes.txt --filter malicious

# Minimum 10 detections for "malicious"
python hashLookup/lookup.py -f hashes.txt --threshold 10
```

#### Source Selection
```bash
# Query only VirusTotal
python hashLookup/lookup.py -f hashes.txt --sources virustotal

# Query VT and MalwareBazaar
python hashLookup/lookup.py -f hashes.txt --sources virustotal,malwarebazaar
```

#### Cache Management
```bash
# Disable cache (always query APIs)
python hashLookup/lookup.py -f hashes.txt --no-cache

# Set cache TTL to 1 hour
python hashLookup/lookup.py -f hashes.txt --cache-ttl 3600
```

#### Rate Limiting
```bash
# Premium VT (1000 req/min)
python hashLookup/lookup.py -f hashes.txt --rate-limit 1000

# Free tier (4 req/min, default)
python hashLookup/lookup.py -f hashes.txt --rate-limit 4
```

#### Blocklist Export
```bash
# Export malicious hashes to blocklist
python hashLookup/lookup.py -f hashes.txt --export-blocklist malicious_hashes.txt
```

## Output Schema

### JSON Format

```json
{
  "metadata": {
    "lookup_date": "2025-11-18T10:00:00Z",
    "total_hashes": 10,
    "sources_queried": ["virustotal", "malwarebazaar"],
    "cache_hits": 3,
    "cache_misses": 7,
    "summary": {
      "malicious": 4,
      "suspicious": 2,
      "clean": 3,
      "unknown": 1
    }
  },
  "results": [
    {
      "hash": "5d41402abc4b2a76b9719d911017c592",
      "hash_type": "md5",
      "verdict": "malicious",
      "detection_ratio": "45/65",
      "confidence": "high",
      "malware_family": "TrickBot",
      "first_seen": "2024-05-15T08:30:00Z",
      "last_seen": "2025-11-10T14:20:00Z",
      "file_type": "PE32",
      "file_size": 245760,
      "sources": {
        "virustotal": {
          "verdict": "malicious",
          "detections": 45,
          "total_engines": 65,
          "malware_names": [
            "Trojan.TrickBot",
            "Win32.TrickBot.A",
            "Backdoor.TrickBot"
          ],
          "tags": ["trojan", "banking", "credential-stealer"],
          "permalink": "https://www.virustotal.com/gui/file/5d41402...",
          "scan_date": "2025-11-18T09:55:00Z"
        },
        "malwarebazaar": {
          "verdict": "malicious",
          "signature": "TrickBot",
          "tags": ["exe", "TrickBot"],
          "permalink": "https://bazaar.abuse.ch/sample/5d41402..."
        }
      },
      "yara_matches": ["TrickBot_Loader", "Banker_Generic"],
      "behavioral_tags": ["credential-theft", "network-c2"],
      "cached": false
    },
    {
      "hash": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "hash_type": "sha1",
      "verdict": "clean",
      "detection_ratio": "0/65",
      "sources": {
        "virustotal": {
          "verdict": "clean",
          "detections": 0,
          "total_engines": 65,
          "permalink": "https://www.virustotal.com/gui/file/aaf4c61..."
        }
      },
      "cached": true
    },
    {
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "hash_type": "sha256",
      "verdict": "unknown",
      "detection_ratio": "0/0",
      "sources": {},
      "cached": false,
      "note": "Hash not found in any database"
    }
  ]
}
```

### CSV Format

```csv
Hash,Type,Verdict,Detection_Ratio,Malware_Family,File_Type,First_Seen,VT_Link,Cached
5d41402abc4b2a76b9719d911017c592,md5,malicious,45/65,TrickBot,PE32,2024-05-15,https://www.virustotal.com/gui/file/5d41402...,false
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d,sha1,clean,0/65,,,2025-11-18,https://www.virustotal.com/gui/file/aaf4c61...,true
```

### HTML Report Format

Interactive HTML with:
- Summary statistics (pie chart)
- Sortable/filterable table
- Color-coded verdicts
- Expandable details per hash
- Export buttons (CSV, JSON)

## Configuration File

### YAML Format (.hashlookup.yml)

```yaml
api_keys:
  virustotal: ${VT_API_KEY}  # From environment
  malwarebazaar: ${MB_API_KEY}
  hybridanalysis: ${HA_API_KEY}

sources:
  enabled:
    - virustotal
    - malwarebazaar

  virustotal:
    priority: 1
    rate_limit: 4  # requests per minute
    timeout: 30

  malwarebazaar:
    priority: 2
    rate_limit: 100
    timeout: 15

cache:
  enabled: true
  backend: sqlite  # sqlite, redis, json
  path: ~/.hashlookup_cache.db
  ttl: 86400  # 24 hours
  max_size: 100000  # max cached entries

processing:
  workers: 5
  retry_attempts: 3
  retry_delay: 5  # seconds

verdicts:
  malicious_threshold: 5  # min detections
  suspicious_threshold: 1

output:
  default_format: json
  color: true
  progress_bar: true
```

## Dependencies

### Required Libraries
```
requests>=2.31.0
aiohttp>=3.9.0         # Async HTTP
asyncio>=3.4.3         # Async processing
python-dotenv>=1.0.0
click>=8.1.0           # CLI framework
rich>=13.0.0           # Terminal formatting
tqdm>=4.66.0           # Progress bars
```

### Optional
```
redis>=5.0.0           # Redis cache backend
stix2>=3.0.0           # STIX export
jinja2>=3.1.0          # HTML report templates
```

## API Integrations

### VirusTotal API v3
```python
GET https://www.virustotal.com/api/v3/files/{hash}
Headers: x-apikey: YOUR_API_KEY
```

### MalwareBazaar
```python
POST https://mb-api.abuse.ch/api/v1/
Data: query=get_info&hash=HASH_VALUE
```

### ThreatFox
```python
POST https://threatfox-api.abuse.ch/api/v1/
Data: {"query": "search_hash", "hash": "HASH_VALUE"}
```

## Testing

### Test Cases

1. **TC-1: Single Hash Lookup**
   - Input: Valid SHA256 hash
   - Expected: Threat data from all sources

2. **TC-2: Batch Processing**
   - Input: File with 100 hashes
   - Expected: All processed with progress bar

3. **TC-3: Cache Hit**
   - Input: Previously queried hash
   - Expected: Instant response from cache

4. **TC-4: Rate Limiting**
   - Input: 20 hashes with 4 req/min limit
   - Expected: Throttled to 5 minutes total

5. **TC-5: Invalid Hash**
   - Input: Malformed hash string
   - Expected: Error message, skip hash

6. **TC-6: API Key Missing**
   - Input: Hash lookup without API key
   - Expected: Graceful error, suggest config

7. **TC-7: Mixed Hash Types**
   - Input: MD5, SHA1, SHA256 hashes
   - Expected: All identified and processed correctly

8. **TC-8: Export Blocklist**
   - Input: Mixed verdict hashes
   - Expected: Only malicious in blocklist file

## Future Enhancements

1. **Automatic File Upload**
   - Upload unknown files to VT for analysis
   - Monitor submission status

2. **Similarity Search**
   - Find similar files by hash (SSDeep, TLSH)
   - Variant detection

3. **Real-time Monitoring**
   - Watch directory for new files
   - Auto-lookup on file creation

4. **Integration with MISP**
   - Export to MISP events
   - Import from MISP feeds

5. **Machine Learning Verdict**
   - ML model for verdict confidence
   - Anomaly detection

6. **Web Dashboard**
   - Upload hashes via web UI
   - View historical lookups
   - Team collaboration

## Known Limitations

- VirusTotal free tier: 4 requests/minute
- MalwareBazaar: Max 100 req/day (free)
- Large batches (>1000 hashes) require time due to rate limits
- Some sources may have limited hash coverage

## Security Considerations

- API keys stored in `.env`, never in code
- HTTPS for all API communications
- No caching of sensitive file contents
- Input validation prevents injection attacks

## Performance Metrics

- Single lookup (cached): < 100ms
- Single lookup (API): 1-3 seconds
- Batch 100 hashes (4 req/min): ~25 minutes
- Batch 100 hashes (cached): < 5 seconds

## References

- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
- [Hybrid Analysis API](https://www.hybrid-analysis.com/docs/api/v2)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
