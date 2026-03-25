# Threat Feed Aggregator - Feature Specification

## Overview

**Feature Name:** Threat Feed Aggregator
**Module:** threatFeedAggregator
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** High
**Target Release:** Phase 4

## Purpose

The Threat Feed Aggregator centralizes threat intelligence from multiple public and private sources, normalizes data to STIX 2.1 format, performs deduplication and correlation, and exports to various platforms (MISP, Splunk, ELK). It enables SOC teams to maintain a unified threat intelligence database with automated updates.

## User Stories

### Primary Use Cases

1. **As a Threat Intelligence Analyst**, I want to aggregate threat feeds from AlienVault OTX, ThreatFox, and URLhaus into a single database for centralized analysis
2. **As a SOC Manager**, I need to schedule automatic threat feed updates every hour and export new IOCs to our SIEM
3. **As an Incident Responder**, I want to search aggregated threat feeds for specific IOCs found during investigations
4. **As a Security Architect**, I need to export threat intelligence to MISP in STIX 2.1 format for threat intelligence sharing
5. **As a Threat Hunter**, I want to correlate IOCs across multiple threat feeds to identify high-confidence indicators

## Functional Requirements

### FR-1: Multi-Source Feed Ingestion
- **Description**: Ingest threat feeds from multiple sources
- **Supported Sources**:
  - AlienVault OTX (Open Threat Exchange)
  - Abuse.ch ThreatFox
  - Abuse.ch URLhaus
  - Abuse.ch MalwareBazaar
  - PhishTank
  - Feodo Tracker
  - Custom RSS/JSON feeds
- **Feed Types**: IP blacklists, domain blacklists, URL lists, file hashes, YARA rules
- **Authentication**: API key management for authenticated feeds

### FR-2: STIX 2.1 Normalization
- **Description**: Convert all feeds to STIX 2.1 format
- **STIX Objects**:
  - Indicator (IOCs)
  - Observable (IP, domain, URL, file hash)
  - Threat Actor
  - Malware
  - Attack Pattern (MITRE ATT&CK)
  - Relationship (links between objects)
- **Mapping**: Source-specific field mapping to STIX properties
- **Validation**: STIX schema validation

### FR-3: Deduplication
- **Description**: Identify and merge duplicate IOCs
- **Dedup Keys**:
  - IP addresses (exact match)
  - Domains (case-insensitive)
  - URLs (normalized)
  - Hashes (case-insensitive)
- **Merge Strategy**: Keep most recent data, aggregate sources
- **Confidence**: Increase confidence score for multi-source IOCs

### FR-4: Correlation Engine
- **Description**: Correlate related IOCs across feeds
- **Correlation Types**:
  - Same malware family
  - Same threat actor/campaign
  - Same C2 infrastructure
  - Related domains (WHOIS, DNS)
  - Related IPs (ASN, geolocation)
- **Relationship Mapping**: Create STIX relationships
- **Scoring**: Calculate correlation confidence

### FR-5: Feed Scheduling
- **Description**: Automate feed updates
- **Schedule Types**:
  - Cron-based scheduling
  - Interval-based (hourly, daily, weekly)
  - On-demand manual updates
- **Features**:
  - Configurable update frequency per source
  - Rate limiting
  - Error handling and retry logic
  - Update history tracking

### FR-6: Storage Backend
- **Description**: Persistent storage for aggregated feeds
- **Storage Options**:
  - SQLite (default, single-file database)
  - PostgreSQL (production, multi-user)
  - MongoDB (document-oriented)
  - Redis (caching layer)
- **Schema**: STIX 2.1 compatible schema
- **Indexing**: Fast lookup by IOC type, source, timestamp
- **Retention**: Configurable data retention policies

### FR-7: Search and Query
- **Description**: Search aggregated threat intelligence
- **Search Criteria**:
  - IOC value (IP, domain, hash, URL)
  - IOC type
  - Source feed
  - Date range
  - Malware family
  - Threat actor
  - Confidence level
  - Tags
- **Query Language**: SQL-like query syntax
- **Results**: Paginated results with relevance scoring

### FR-8: Export Capabilities
- **Description**: Export to various formats and platforms
- **Export Formats**:
  - STIX 2.1 JSON
  - CSV
  - JSON Lines (JSONL)
  - XML
  - OpenIOC
- **Platform Integration**:
  - MISP (via API)
  - Splunk (via HTTP Event Collector)
  - ELK (via Logstash)
  - TheHive
  - Custom webhooks

### FR-9: Filtering and Whitelisting
- **Description**: Filter out false positives and known-good indicators
- **Whitelist Sources**:
  - Custom whitelist file
  - Alexa Top 1M
  - Cisco Umbrella Top 1M
  - Cloud provider IPs (AWS, Azure, GCP)
- **Filtering Rules**:
  - Exclude private IPs (configurable)
  - Exclude CDN domains
  - Minimum confidence threshold
  - Age-based filtering

### FR-10: Threat Actor Attribution
- **Description**: Track threat actor campaigns
- **Attribution Sources**:
  - MITRE ATT&CK groups
  - Malpedia actor profiles
  - Feed metadata
- **Tracking**:
  - IOCs per threat actor
  - Campaign timeline
  - TTPs (Tactics, Techniques, Procedures)
  - Associated malware

### FR-11: Enrichment
- **Description**: Enrich IOCs with additional context
- **Enrichment Sources**:
  - DNS resolution (A, AAAA, MX, NS records)
  - WHOIS data
  - Geolocation (IP)
  - ASN information
  - TLS certificate data
- **Integration**: Leverage existing Domain/IP Intel tool
- **Caching**: Cache enrichment data to reduce API calls

### FR-12: Confidence Scoring
- **Description**: Calculate confidence score for each IOC
- **Scoring Factors**:
  - Number of sources reporting (weight: 40%)
  - Source reputation (weight: 30%)
  - Recency (weight: 20%)
  - Correlation strength (weight: 10%)
- **Scale**: 0-100 confidence score
- **Classification**: Low (0-30), Medium (31-70), High (71-100)

### FR-13: Statistics and Metrics
- **Description**: Track feed ingestion metrics
- **Metrics**:
  - IOCs per source
  - IOCs per type (IP, domain, URL, hash)
  - Deduplication rate
  - Update success/failure rate
  - API quota usage
  - Storage size
  - Query performance
- **Visualization**: Generate statistics reports
- **Dashboards**: Optional web dashboard

### FR-14: CLI Interface
- **Description**: Comprehensive command-line interface
- **Commands**:
  - `update` - Update all or specific feeds
  - `search` - Search for IOCs
  - `export` - Export data
  - `stats` - Show statistics
  - `config` - Manage configuration
  - `whitelist` - Manage whitelists
- **Output**: JSON, CSV, table formats

### FR-15: API Server (Optional)
- **Description**: REST API for threat intelligence queries
- **Endpoints**:
  - `GET /api/ioc/{value}` - Lookup IOC
  - `GET /api/search` - Search IOCs
  - `GET /api/stats` - Get statistics
  - `POST /api/export` - Export data
- **Authentication**: API key authentication
- **Rate Limiting**: Configurable rate limits

## Non-Functional Requirements

### NFR-1: Performance
- **Requirement**: Ingest 100,000 IOCs in under 5 minutes
- **Implementation**: Batch processing, bulk inserts, indexing
- **Monitoring**: Performance metrics logging

### NFR-2: Scalability
- **Requirement**: Support millions of IOCs in database
- **Implementation**: Database indexing, partitioning, archival
- **Testing**: Load testing with large datasets

### NFR-3: Reliability
- **Requirement**: 99.9% feed update success rate
- **Implementation**: Retry logic, error handling, alerting
- **Recovery**: Automatic recovery from failures

### NFR-4: Security
- **Requirement**: Secure API key storage and transmission
- **Implementation**: Encrypted storage, HTTPS for all API calls
- **Validation**: Input sanitization, SQL injection prevention

### NFR-5: Usability
- **Requirement**: Easy setup with minimal configuration
- **Implementation**: Sensible defaults, setup wizard
- **Documentation**: Comprehensive user guide

## Technical Design

### Architecture

```
threatFeedAggregator/
├── aggregator.py          # Main feed aggregation engine
├── sources/              # Feed source implementations
│   ├── __init__.py
│   ├── otx.py           # AlienVault OTX
│   ├── threatfox.py     # Abuse.ch ThreatFox
│   ├── urlhaus.py       # Abuse.ch URLhaus
│   ├── malwarebazaar.py # Abuse.ch MalwareBazaar
│   ├── phishtank.py     # PhishTank
│   └── custom.py        # Custom feed parser
├── stix/                # STIX 2.1 converter
│   ├── __init__.py
│   ├── converter.py     # Feed to STIX converter
│   └── validator.py     # STIX validation
├── storage/             # Database backends
│   ├── __init__.py
│   ├── sqlite.py        # SQLite backend
│   └── postgres.py      # PostgreSQL backend
├── exporters/           # Export modules
│   ├── __init__.py
│   ├── misp.py          # MISP integration
│   ├── splunk.py        # Splunk HEC
│   └── elk.py           # ELK integration
├── cache/               # Cache directory
└── config/              # Configuration files
    └── feeds.yaml       # Feed configuration
```

### Core Classes

```python
class FeedSource:
    """Base class for threat feed sources"""
    def fetch_feed(self) -> List[Dict]
    def parse_feed(self, raw_data: bytes) -> List[Dict]
    def normalize_to_stix(self, items: List[Dict]) -> List[STIXObject]

class FeedAggregator:
    """Main aggregation engine"""
    def __init__(self, config: Dict, storage: Storage)
    def update_all_feeds(self) -> Dict[str, int]
    def update_feed(self, source_name: str) -> int
    def deduplicate(self, iocs: List[Dict]) -> List[Dict]
    def correlate(self, iocs: List[Dict]) -> List[Relationship]

class Storage:
    """Abstract storage backend"""
    def store_iocs(self, iocs: List[Dict]) -> int
    def search_iocs(self, query: Dict) -> List[Dict]
    def get_stats(self) -> Dict
    def expire_old_data(self, days: int) -> int

class STIXConverter:
    """Convert feeds to STIX 2.1"""
    def create_indicator(self, ioc: Dict) -> Indicator
    def create_observable(self, ioc: Dict) -> Observable
    def create_relationship(self, source_id: str, target_id: str, rel_type: str) -> Relationship
    def validate_stix(self, stix_object: STIXObject) -> bool

class Exporter:
    """Base class for exporters"""
    def export(self, iocs: List[Dict], format: str) -> bytes
```

### Data Structures

#### Aggregated IOC
```python
{
    "id": "indicator--uuid",
    "type": "indicator",
    "spec_version": "2.1",
    "created": "2025-11-20T10:00:00.000Z",
    "modified": "2025-11-20T10:00:00.000Z",
    "name": "Malicious IP 1.2.3.4",
    "description": "C2 server for Emotet",
    "indicator_types": ["malicious-activity"],
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
    "pattern_type": "stix",
    "valid_from": "2025-11-20T10:00:00.000Z",
    "valid_until": "2025-12-20T10:00:00.000Z",
    "labels": ["malware", "emotet", "c2"],
    "confidence": 85,
    "sources": [
        {
            "name": "AlienVault OTX",
            "url": "https://otx.alienvault.com/pulse/123",
            "first_seen": "2025-11-15T08:00:00.000Z"
        },
        {
            "name": "ThreatFox",
            "url": "https://threatfox.abuse.ch/browse/malware/emotet/",
            "first_seen": "2025-11-16T12:00:00.000Z"
        }
    ],
    "enrichment": {
        "asn": "AS12345",
        "country": "RU",
        "org": "Evil Hosting Ltd"
    },
    "related_iocs": [
        "indicator--related-domain-uuid",
        "malware--emotet-uuid"
    ]
}
```

### Algorithms

#### Deduplication Algorithm
```python
1. For each new IOC:
   a. Normalize value (lowercase, strip whitespace)
   b. Calculate hash key (type + normalized value)
   c. Check if hash key exists in database
   d. If exists:
      - Merge sources list
      - Update modified timestamp
      - Recalculate confidence score
   e. If not exists:
      - Insert as new IOC
2. Return deduplicated count
```

#### Correlation Algorithm
```python
1. Group IOCs by malware family
2. For each group:
   a. Extract all IPs, domains, URLs
   b. Find common patterns (IP ranges, domain registrars)
   c. Create "related-to" relationships
3. Group IOCs by threat actor
4. For each threat actor:
   a. Link all associated IOCs
   b. Create "attributed-to" relationships
5. Return relationship list
```

## Command-Line Interface

### Syntax
```bash
python aggregator.py [command] [options]
```

### Commands

#### Update Command
```bash
# Update all feeds
python aggregator.py update

# Update specific feed
python aggregator.py update --source otx

# Update with verbose output
python aggregator.py update --verbose

# Force update (ignore cache)
python aggregator.py update --force
```

#### Search Command
```bash
# Search for specific IOC
python aggregator.py search "1.2.3.4"

# Search by type
python aggregator.py search --type ip --min-confidence 70

# Search by source
python aggregator.py search --source threatfox --format json

# Search by date range
python aggregator.py search --since "2025-11-01" --until "2025-11-20"

# Search by malware family
python aggregator.py search --malware emotet --format csv
```

#### Export Command
```bash
# Export all IOCs to STIX
python aggregator.py export --format stix --output iocs.json

# Export to MISP
python aggregator.py export --platform misp --misp-url https://misp.local

# Export to Splunk
python aggregator.py export --platform splunk --hec-url https://splunk:8088

# Export filtered IOCs
python aggregator.py export --min-confidence 80 --type ip --format csv
```

#### Stats Command
```bash
# Show overall statistics
python aggregator.py stats

# Show source-specific stats
python aggregator.py stats --source otx

# Show IOC type distribution
python aggregator.py stats --breakdown type
```

#### Config Command
```bash
# Show current configuration
python aggregator.py config show

# Add new feed source
python aggregator.py config add-source custom --url https://feed.example.com/iocs.json

# Remove feed source
python aggregator.py config remove-source custom

# Set update interval
python aggregator.py config set-interval otx 3600  # 1 hour
```

### Unified CLI Integration
```bash
# Via vlair
vlair threat update
vlair threat search "1.2.3.4"
vlair threat export --format stix
vlair threat stats
```

### Examples

```bash
# Example 1: Initial setup and first update
python aggregator.py config init
python aggregator.py update --verbose

# Example 2: Search for an IP found during incident
python aggregator.py search "192.168.1.1" --format txt

# Example 3: Export high-confidence IOCs to MISP
python aggregator.py export --min-confidence 80 --platform misp

# Example 4: Scheduled update (via cron)
0 * * * * /usr/bin/python3 /path/to/aggregator.py update --quiet

# Example 5: Search for Emotet IOCs
python aggregator.py search --malware emotet --format json --output emotet_iocs.json

# Example 6: Get statistics for the last 7 days
python aggregator.py stats --since "7 days ago"
```

## Output Schema

### JSON Search Results
```json
{
  "metadata": {
    "tool": "threat_feed_aggregator",
    "version": "1.0.0",
    "query_date": "2025-11-20T10:00:00Z",
    "query": {
      "value": "1.2.3.4",
      "type": "ip",
      "min_confidence": 70
    },
    "results_count": 1
  },
  "results": [
    {
      "id": "indicator--abc123",
      "value": "1.2.3.4",
      "type": "ipv4-addr",
      "first_seen": "2025-11-15T08:00:00Z",
      "last_seen": "2025-11-20T10:00:00Z",
      "confidence": 85,
      "labels": ["malware", "emotet", "c2"],
      "malware_family": "Emotet",
      "threat_actor": null,
      "sources": [
        {
          "name": "AlienVault OTX",
          "url": "https://otx.alienvault.com/pulse/123",
          "first_seen": "2025-11-15T08:00:00.000Z"
        }
      ],
      "enrichment": {
        "asn": "AS12345",
        "country": "RU",
        "org": "Evil Hosting Ltd"
      }
    }
  ]
}
```

### CSV Export
```csv
Value,Type,Confidence,Labels,Malware Family,First Seen,Last Seen,Sources
1.2.3.4,ipv4-addr,85,"malware,emotet,c2",Emotet,2025-11-15T08:00:00Z,2025-11-20T10:00:00Z,"AlienVault OTX,ThreatFox"
evil.com,domain,92,"phishing",PhishKit,2025-11-18T12:00:00Z,2025-11-20T10:00:00Z,PhishTank
```

## Configuration

### Configuration File: `~/.threatFeedAggregator/config.yaml`

```yaml
# Threat Feed Aggregator Configuration

# Data Storage
storage:
  backend: sqlite                    # sqlite, postgresql, mongodb
  path: ~/.threatFeedAggregator/db.sqlite
  # For PostgreSQL:
  # host: localhost
  # port: 5432
  # database: threatfeeds
  # user: postgres
  # password: secret

# Feed Sources
sources:
  - name: otx
    enabled: true
    api_key: ${OTX_API_KEY}
    update_interval: 3600           # 1 hour
    url: https://otx.alienvault.com/api/v1/pulses/subscribed

  - name: threatfox
    enabled: true
    api_key: null                   # Public feed
    update_interval: 1800           # 30 minutes
    url: https://threatfox-api.abuse.ch/api/v1/

  - name: urlhaus
    enabled: true
    api_key: null
    update_interval: 1800
    url: https://urlhaus-api.abuse.ch/v1/urls/recent/

  - name: malwarebazaar
    enabled: true
    api_key: null
    update_interval: 3600
    url: https://mb-api.abuse.ch/api/v1/

  - name: phishtank
    enabled: false
    api_key: ${PHISHTANK_KEY}
    update_interval: 7200           # 2 hours
    url: http://data.phishtank.com/data/online-valid.json

# Deduplication
deduplication:
  enabled: true
  merge_strategy: keep_highest_confidence

# Filtering
filtering:
  exclude_private_ips: true
  exclude_localhost: true
  min_confidence: 30
  whitelist_path: ~/.threatFeedAggregator/whitelist.txt
  use_alexa_whitelist: false

# Data Retention
retention:
  max_age_days: 90                  # Delete IOCs older than 90 days
  archive: true                     # Archive before deletion
  archive_path: ~/.threatFeedAggregator/archive/

# Export
export:
  default_format: stix
  misp:
    url: https://misp.local
    api_key: ${MISP_API_KEY}
    verify_ssl: true
  splunk:
    hec_url: https://splunk:8088
    hec_token: ${SPLUNK_HEC_TOKEN}

# Performance
performance:
  batch_size: 1000
  worker_threads: 4
  max_memory_mb: 512

# Logging
logging:
  level: INFO                       # DEBUG, INFO, WARNING, ERROR
  file: ~/.threatFeedAggregator/aggregator.log
  max_size_mb: 100
  backup_count: 5
```

## Dependencies

### Python Packages
```
requests>=2.31.0                  # HTTP requests
python-dotenv>=1.0.0              # Environment variables
stix2>=3.0.0                      # STIX 2.1 library
pymisp>=2.4.0                     # MISP integration
pyyaml>=6.0                       # Config file parsing
sqlalchemy>=2.0.0                 # Database ORM
psycopg2-binary>=2.9.0            # PostgreSQL driver
redis>=5.0.0                      # Redis caching
schedule>=1.2.0                   # Job scheduling
tqdm>=4.66.0                      # Progress bars
```

## Testing Strategy

### Unit Tests
1. **Feed Parsing**: Test each source parser
2. **STIX Conversion**: Test feed to STIX conversion
3. **Deduplication**: Test dedup logic
4. **Correlation**: Test correlation engine
5. **Storage**: Test database operations

### Integration Tests
1. **End-to-End**: Feed fetch → parse → store → export
2. **Multi-Source**: Test aggregation from multiple sources
3. **Export**: Test export to MISP, Splunk, ELK
4. **Scheduling**: Test automated updates

### Test Data
- Mock API responses from each source
- Sample STIX 2.1 objects
- Test database with known IOCs

## Future Enhancements

### Phase 2
- **Machine Learning**: Anomaly detection, false positive reduction
- **Threat Actor Tracking**: Advanced attribution
- **Custom Feeds**: Support for more feed formats
- **Real-time Streaming**: WebSocket/SSE for real-time updates
- **Collaborative Intelligence**: Share private feeds with trusted partners

### Phase 3
- **Web Dashboard**: Visual threat intelligence platform
- **Alerting**: Email/Slack alerts for new high-confidence IOCs
- **Hunting Workflows**: Integrated threat hunting capabilities
- **Playbook Integration**: Automated response playbooks
- **TAXII Server**: Publish feeds via TAXII 2.1

## References

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [Abuse.ch Threat Feeds](https://abuse.ch/)
- [MISP API Documentation](https://www.misp-project.org/openapi/)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)

---

**Last Updated:** 2025-11-20
**Status:** Specification Complete - Ready for Implementation
