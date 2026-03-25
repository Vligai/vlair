# Domain/IP Intelligence - Feature Specification

## Overview

**Feature Name:** Domain/IP Intelligence
**Module:** domainIpIntel
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** High
**Target Release:** Phase 3

## Purpose

The Domain/IP Intelligence tool provides comprehensive threat intelligence and reputation analysis for IP addresses and domain names. It aggregates data from multiple sources including WHOIS, DNS, GeoIP, threat feeds, and security databases to help analysts quickly assess the risk level of network indicators.

## User Stories

### Primary Use Cases

1. **As a SOC Analyst**, I want to quickly check the reputation of a suspicious IP address to determine if it's malicious
2. **As an Incident Responder**, I need to gather WHOIS and DNS information for a domain involved in phishing to identify the attacker
3. **As a Threat Hunter**, I want to check multiple IPs against threat intelligence feeds and generate a risk-scored report
4. **As a Security Researcher**, I need to analyze domain registration patterns to identify potential typosquatting campaigns
5. **As a Network Administrator**, I want to verify if an IP connecting to our network has a history of malicious activity

## Functional Requirements

### FR-1: IP Address Intelligence
- **Description**: Comprehensive IP address analysis
- **Data Points**:
  - Geolocation (country, city, coordinates)
  - ASN (Autonomous System Number) and organization
  - ISP/hosting provider
  - Reverse DNS (PTR record)
  - IP reputation score
  - Threat intelligence data
  - Open ports (optional scan)
  - Historical data (first/last seen)
- **Sources**: MaxMind GeoIP, AbuseIPDB, IPVoid, VirusTotal, IPQualityScore

### FR-2: Domain Intelligence
- **Description**: Comprehensive domain analysis
- **Data Points**:
  - WHOIS information (registrar, registrant, dates)
  - DNS records (A, AAAA, MX, NS, TXT, CNAME)
  - Subdomain enumeration (optional)
  - Domain age
  - SSL certificate information
  - Website categorization
  - Threat intelligence data
  - Similar/related domains
- **Sources**: WHOIS servers, DNS queries, URLhaus, PhishTank, Google Safe Browsing

### FR-3: Reputation Scoring
- **Description**: Calculate aggregate reputation score
- **Scoring Factors**:
  - Threat feed presence
  - Abuse reports count
  - Blacklist appearances
  - Domain age (new domains more suspicious)
  - WHOIS privacy usage
  - SSL certificate validity
  - Historical malicious activity
- **Score Range**: 0-100 (0=clean, 100=malicious)
- **Risk Levels**: Clean, Low, Medium, High, Critical

### FR-4: Threat Intelligence Lookup
- **Description**: Check against multiple threat feeds
- **Sources**:
  - AbuseIPDB (IP reputation)
  - URLhaus (malicious URLs)
  - PhishTank (phishing domains)
  - Emerging Threats (IP blocklists)
  - AlienVault OTX (Open Threat Exchange)
  - VirusTotal (URL/domain scanning)
  - ThreatFox (IOC database)
  - Shodan (optional, for open ports)
- **Data Retrieved**:
  - Threat category (malware, phishing, spam, etc.)
  - Confidence score
  - First/last seen
  - Associated campaigns
  - Related IOCs

### FR-5: WHOIS Lookup
- **Description**: Query WHOIS databases for domain/IP ownership
- **Data Extracted**:
  - Registrar information
  - Registrant details (name, email, org)
  - Registration date
  - Expiration date
  - Name servers
  - Status codes
  - WHOIS privacy detection
- **Features**:
  - Rate limiting for WHOIS servers
  - Retry logic for failures
  - Caching to reduce queries

### FR-6: DNS Analysis
- **Description**: Comprehensive DNS record analysis
- **Record Types**:
  - A (IPv4 addresses)
  - AAAA (IPv6 addresses)
  - MX (mail servers)
  - NS (name servers)
  - TXT (text records, SPF, DMARC)
  - CNAME (canonical names)
  - SOA (start of authority)
  - PTR (reverse DNS)
- **Analysis**:
  - DNS history tracking
  - Suspicious record patterns
  - Fast-flux detection
  - DNS hijacking indicators

### FR-7: GeoIP Lookup
- **Description**: Geographic location of IP addresses
- **Data Points**:
  - Country (ISO code and name)
  - Region/State
  - City
  - Coordinates (latitude/longitude)
  - Timezone
  - Postal code
- **Database**: MaxMind GeoLite2 (free) or GeoIP2 (commercial)
- **Visualization**: Optional map output

### FR-8: ASN Lookup
- **Description**: Autonomous System Number information
- **Data Points**:
  - ASN number
  - Organization name
  - Country
  - Prefix ranges
  - Peer count
- **Use Case**: Identify hosting provider and network ownership

### FR-9: SSL Certificate Analysis
- **Description**: Analyze SSL/TLS certificates for domains
- **Data Points**:
  - Issuer
  - Subject
  - Valid from/to dates
  - Certificate transparency logs
  - Subject Alternative Names (SANs)
  - Self-signed detection
  - Expiration warnings
- **Security**: Identify suspicious certificates

### FR-10: Subdomain Enumeration
- **Description**: Discover subdomains for a domain
- **Techniques**:
  - DNS brute-forcing (wordlist)
  - Certificate transparency logs
  - Search engine queries
  - DNS zone transfer (if allowed)
- **Output**: List of discovered subdomains with IPs
- **Use Case**: Attack surface mapping

### FR-11: Batch Processing
- **Description**: Analyze multiple IPs/domains efficiently
- **Input Methods**:
  - Command-line (space/comma separated)
  - File (one per line)
  - CSV with column specification
  - Standard input (pipe)
- **Features**:
  - Parallel processing
  - Progress indicators
  - Rate limiting per source
  - Caching for efficiency

### FR-12: Historical Data Tracking
- **Description**: Track changes over time
- **Features**:
  - Store lookup results locally
  - Compare current vs. historical data
  - Detect changes (WHOIS, DNS, reputation)
  - Timeline visualization
- **Storage**: SQLite database

### FR-13: Related Indicators
- **Description**: Find related IPs and domains
- **Features**:
  - IPs on same subnet
  - Domains on same IP (reverse IP lookup)
  - Domains with same WHOIS registrant
  - Domains with similar names (typosquatting)
  - SSL certificate sharing
- **Use Case**: Campaign tracking

### FR-14: Passive DNS
- **Description**: Query passive DNS databases
- **Sources**:
  - CIRCL Passive DNS
  - Farsight DNSDB
  - VirusTotal
- **Data**: Historical DNS resolutions
- **Use Case**: Track domain/IP relationships over time

### FR-15: Export & Reporting
- **Description**: Export intelligence in multiple formats
- **Formats**:
  - JSON (detailed, all data)
  - CSV (tabular summary)
  - HTML (interactive report)
  - Markdown (documentation)
  - STIX 2.1 (threat intelligence)
  - MISP (event format)
- **Customization**: Configurable output fields

## Non-Functional Requirements

### NFR-1: Performance
- Single IP/domain lookup in < 5 seconds
- Batch of 100 items in < 3 minutes (with rate limiting)
- Cache hits < 100ms
- Parallel queries where possible

### NFR-2: Reliability
- Handle API failures gracefully
- Retry with exponential backoff
- Fallback to alternative sources
- Network timeout protection (15s per query)

### NFR-3: Accuracy
- Up-to-date threat intelligence (< 24h old)
- Accurate GeoIP (95%+ accuracy)
- Proper handling of WHOIS privacy
- Clear confidence scoring

### NFR-4: Usability
- Simple CLI interface
- Color-coded risk levels
- Clear, actionable output
- Verbose mode for debugging

### NFR-5: Privacy
- No data sent to third parties without consent
- API keys stored securely
- Optional anonymous queries
- Local caching to minimize external queries

## Technical Design

### Architecture

```
┌─────────────────┐
│  Input Handler  │
│  (IP/Domain)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Validator      │
│  (IP/Domain)    │
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
│  (Parallel, Rate Limit) │
└────────┬────────────────┘
         │
         ├──────┬──────┬──────┬──────┐
         ▼      ▼      ▼      ▼      ▼
    ┌────────────────────────────┐
    │    Intelligence Sources    │
    ├────────────────────────────┤
    │ - WHOIS Lookup             │
    │ - DNS Resolver             │
    │ - GeoIP Database           │
    │ - AbuseIPDB API            │
    │ - VirusTotal API           │
    │ - URLhaus API              │
    │ - PhishTank API            │
    │ - Shodan API (optional)    │
    └────────┬───────────────────┘
             │
             ▼
    ┌────────────────────┐
    │  Data Aggregator   │
    │  & Risk Scorer     │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  Report Generator  │
    │  (JSON/HTML/CSV)   │
    └────────────────────┘
```

### Core Components

#### IPValidator / DomainValidator
```python
class IPValidator:
    def is_valid(self, ip: str) -> bool:
        """Check if valid IPv4/IPv6"""

    def is_private(self, ip: str) -> bool:
        """Check if private IP range"""

class DomainValidator:
    def is_valid(self, domain: str) -> bool:
        """Check if valid domain format"""

    def extract_tld(self, domain: str) -> str:
        """Extract top-level domain"""
```

#### RiskScorer
```python
class RiskScorer:
    def calculate_ip_score(self, intel_data: Dict) -> int:
        """Calculate IP risk score (0-100)"""

    def calculate_domain_score(self, intel_data: Dict) -> int:
        """Calculate domain risk score (0-100)"""

    def classify_risk(self, score: int) -> str:
        """Return risk level: Clean/Low/Medium/High/Critical"""
```

#### ThreatIntelSource (Abstract)
```python
class ThreatIntelSource(ABC):
    @abstractmethod
    async def lookup_ip(self, ip: str) -> Dict:
        """Lookup IP intelligence"""

    @abstractmethod
    async def lookup_domain(self, domain: str) -> Dict:
        """Lookup domain intelligence"""
```

### Data Structures

```python
@dataclass
class IPIntelligence:
    ip_address: str
    ip_type: str  # ipv4, ipv6
    geolocation: GeoLocation
    asn: ASNInfo
    reverse_dns: Optional[str]
    reputation_score: int  # 0-100
    risk_level: str  # Clean/Low/Medium/High/Critical
    threat_data: Dict[str, ThreatInfo]
    open_ports: List[int]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    metadata: Dict[str, Any]

@dataclass
class DomainIntelligence:
    domain: str
    whois: WHOISInfo
    dns_records: Dict[str, List[str]]
    ip_addresses: List[str]
    domain_age_days: int
    ssl_certificate: Optional[SSLCertInfo]
    reputation_score: int
    risk_level: str
    threat_data: Dict[str, ThreatInfo]
    subdomains: List[str]
    related_domains: List[str]
    metadata: Dict[str, Any]

@dataclass
class GeoLocation:
    country_code: str
    country_name: str
    region: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: Optional[str]

@dataclass
class WHOISInfo:
    registrar: Optional[str]
    registrant_name: Optional[str]
    registrant_email: Optional[str]
    registrant_org: Optional[str]
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    updated_date: Optional[datetime]
    name_servers: List[str]
    status: List[str]
    privacy_protected: bool
```

## Command-Line Interface

### Syntax

```bash
python domainIpIntel/intel.py [TARGET] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `target` | string | Yes* | IP address or domain name |

*Or use `--file` for batch

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--file` | `-f` | string | - | File with IPs/domains (one per line) |
| `--type` | `-t` | string | auto | Target type (ip/domain/auto) |
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | | string | json | Output format (json/csv/html/md/stix) |
| `--sources` | `-s` | string | all | Comma-separated intel sources |
| `--no-whois` | | flag | False | Skip WHOIS lookup |
| `--no-dns` | | flag | False | Skip DNS lookup |
| `--no-geo` | | flag | False | Skip GeoIP lookup |
| `--no-threats` | | flag | False | Skip threat intelligence |
| `--subdomains` | | flag | False | Enumerate subdomains (domains only) |
| `--ports` | | flag | False | Scan open ports (IPs only) |
| `--passive-dns` | | flag | False | Query passive DNS |
| `--related` | | flag | False | Find related indicators |
| `--cache` | | flag | True | Use cache (--no-cache to disable) |
| `--cache-ttl` | | int | 86400 | Cache TTL in seconds |
| `--verbose` | `-v` | flag | False | Verbose output |
| `--api-keys` | | string | - | Path to API keys file |

### Examples

#### Single Lookup
```bash
# Lookup IP address
python domainIpIntel/intel.py 192.0.2.1

# Lookup domain
python domainIpIntel/intel.py example.com
```

#### Comprehensive Analysis
```bash
# Full domain analysis with subdomains
python domainIpIntel/intel.py malicious.com --subdomains --related

# Full IP analysis with port scan
python domainIpIntel/intel.py 192.0.2.50 --ports --passive-dns
```

#### Batch Processing
```bash
# Analyze IPs from file
python domainIpIntel/intel.py --file ips.txt --format csv -o results.csv

# Analyze domains
python domainIpIntel/intel.py --file domains.txt --format html -o report.html
```

#### Selective Analysis
```bash
# Only WHOIS and DNS
python domainIpIntel/intel.py example.com --no-geo --no-threats

# Only threat intelligence
python domainIpIntel/intel.py example.com --no-whois --no-dns --no-geo
```

#### Source Selection
```bash
# Only use AbuseIPDB and VirusTotal
python domainIpIntel/intel.py 192.0.2.1 --sources abuseipdb,virustotal

# Skip specific sources
python domainIpIntel/intel.py example.com --no-threats
```

## Output Schema

### JSON Format (IP Address)

```json
{
  "target": "192.0.2.50",
  "type": "ipv4",
  "lookup_date": "2025-11-18T10:00:00Z",
  "reputation": {
    "score": 85,
    "risk_level": "High",
    "confidence": 0.92
  },
  "geolocation": {
    "country_code": "CN",
    "country_name": "China",
    "region": "Beijing",
    "city": "Beijing",
    "latitude": 39.9042,
    "longitude": 116.4074,
    "timezone": "Asia/Shanghai"
  },
  "asn": {
    "number": 4134,
    "organization": "Chinanet",
    "country": "CN",
    "prefix": "192.0.2.0/24"
  },
  "reverse_dns": "mail.example.com",
  "threat_intelligence": {
    "abuseipdb": {
      "abuse_confidence_score": 100,
      "usage_type": "Data Center/Web Hosting/Transit",
      "is_whitelisted": false,
      "total_reports": 45,
      "last_reported": "2025-11-17T15:30:00Z",
      "categories": ["Port Scan", "Brute-Force"],
      "permalink": "https://www.abuseipdb.com/check/192.0.2.50"
    },
    "virustotal": {
      "malicious_votes": 12,
      "suspicious_votes": 3,
      "harmless_votes": 1,
      "detected_urls": 5,
      "permalink": "https://www.virustotal.com/gui/ip-address/192.0.2.50"
    },
    "emerging_threats": {
      "listed": true,
      "blocklists": ["compromised", "tor-exit-node"],
      "first_seen": "2025-10-15"
    }
  },
  "open_ports": [22, 80, 443, 8080],
  "passive_dns": [
    {
      "domain": "phishing-site.com",
      "first_seen": "2025-11-10",
      "last_seen": "2025-11-17"
    }
  ],
  "metadata": {
    "cached": false,
    "query_time_ms": 3452,
    "sources_queried": 5
  }
}
```

### JSON Format (Domain)

```json
{
  "target": "phishing-example.com",
  "type": "domain",
  "lookup_date": "2025-11-18T10:00:00Z",
  "reputation": {
    "score": 78,
    "risk_level": "High",
    "confidence": 0.88
  },
  "whois": {
    "registrar": "NameCheap, Inc.",
    "registrant_name": "REDACTED FOR PRIVACY",
    "registrant_email": "REDACTED FOR PRIVACY",
    "registrant_org": "Privacy service",
    "creation_date": "2025-11-15T00:00:00Z",
    "expiration_date": "2026-11-15T00:00:00Z",
    "updated_date": "2025-11-15T00:00:00Z",
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "status": ["clientTransferProhibited"],
    "privacy_protected": true
  },
  "domain_age_days": 3,
  "dns_records": {
    "A": ["192.0.2.50"],
    "AAAA": [],
    "MX": ["mail.phishing-example.com"],
    "NS": ["ns1.example.com", "ns2.example.com"],
    "TXT": ["v=spf1 -all"]
  },
  "ip_addresses": ["192.0.2.50"],
  "ssl_certificate": {
    "issuer": "Let's Encrypt",
    "subject": "phishing-example.com",
    "valid_from": "2025-11-15",
    "valid_to": "2026-02-13",
    "self_signed": false,
    "sans": ["phishing-example.com", "www.phishing-example.com"]
  },
  "threat_intelligence": {
    "phishtank": {
      "listed": true,
      "verified": true,
      "submission_time": "2025-11-17T10:00:00Z",
      "target": "PayPal",
      "permalink": "https://www.phishtank.com/phish_detail.php?phish_id=12345"
    },
    "urlhaus": {
      "listed": true,
      "threat": "phishing",
      "tags": ["phishing", "paypal"],
      "first_seen": "2025-11-17"
    },
    "google_safe_browsing": {
      "unsafe": true,
      "threat_types": ["SOCIAL_ENGINEERING"]
    }
  },
  "subdomains": [
    "www.phishing-example.com",
    "mail.phishing-example.com",
    "login.phishing-example.com"
  ],
  "related_domains": [
    "phishing-example.net",
    "phishing-exarnple.com"
  ],
  "metadata": {
    "cached": false,
    "query_time_ms": 5234
  }
}
```

## Configuration File

### YAML Format (.domainipintel.yml)

```yaml
api_keys:
  abuseipdb: ${ABUSEIPDB_KEY}
  virustotal: ${VT_API_KEY}
  shodan: ${SHODAN_API_KEY}
  urlhaus: ""  # No key required
  phishtank: ${PHISHTANK_KEY}

sources:
  enabled:
    - whois
    - dns
    - geoip
    - abuseipdb
    - virustotal
    - urlhaus
    - phishtank

  abuseipdb:
    enabled: true
    max_age_days: 90

  virustotal:
    enabled: true

  shodan:
    enabled: false  # Optional

geoip:
  database_path: ~/.geoip/GeoLite2-City.mmdb
  auto_update: true

cache:
  enabled: true
  backend: sqlite
  path: ~/.domainipintel_cache.db
  ttl: 86400

scoring:
  weights:
    threat_intel: 0.4
    domain_age: 0.2
    whois_privacy: 0.1
    blacklist_count: 0.3

  thresholds:
    clean: 0-20
    low: 21-40
    medium: 41-60
    high: 61-80
    critical: 81-100

output:
  default_format: json
  color: true
  verbose: false
```

## Dependencies

### Required Libraries
```
dnspython>=2.4.0          # DNS queries
python-whois>=0.8.0       # WHOIS lookups
geoip2>=4.7.0             # GeoIP database
requests>=2.31.0
aiohttp>=3.9.0            # Async HTTP
validators>=0.22.0        # Domain/IP validation
tldextract>=5.0.0         # TLD extraction
```

### Optional
```
shodan>=1.31.0            # Shodan API
python-nmap>=0.7.1        # Port scanning
pyOpenSSL>=23.3.0         # SSL certificate parsing
stix2>=3.0.0              # STIX export
```

## Testing

### Test Cases

1. **TC-1: Valid IP Lookup**
   - Input: Public IP address
   - Expected: Complete intelligence report

2. **TC-2: Valid Domain Lookup**
   - Input: Legitimate domain
   - Expected: WHOIS, DNS, threat data

3. **TC-3: Malicious IP Detection**
   - Input: Known malicious IP
   - Expected: High risk score, threat alerts

4. **TC-4: Phishing Domain Detection**
   - Input: Known phishing domain
   - Expected: High risk score, PhishTank listing

5. **TC-5: Private IP Handling**
   - Input: 192.168.1.1
   - Expected: Skip threat lookups, return basic info

6. **TC-6: Invalid Input**
   - Input: Malformed IP/domain
   - Expected: Error message

7. **TC-7: Batch Processing**
   - Input: File with 50 mixed IPs/domains
   - Expected: All processed correctly

8. **TC-8: Cache Hit**
   - Input: Previously queried IP
   - Expected: Instant response from cache

## Future Enhancements

1. **Real-Time Monitoring**
   - Monitor IPs/domains continuously
   - Alert on reputation changes

2. **Typosquatting Detection**
   - Generate domain permutations
   - Check if registered

3. **Brand Monitoring**
   - Monitor for domains similar to your brand
   - Phishing campaign detection

4. **Sandbox Integration**
   - Submit URLs to sandboxes
   - Get behavioral analysis

5. **Blockchain Analysis**
   - Crypto wallet tracking
   - Ransomware payment tracking

6. **Custom Threat Feeds**
   - Import custom IOC lists
   - Private threat intelligence

## Known Limitations

- WHOIS rate limiting may slow batch processing
- Some WHOIS servers block automated queries
- GeoIP accuracy varies (especially for VPNs)
- Free API tiers have request limits
- Passive DNS requires paid subscription

## Security Considerations

- API keys stored securely in .env
- HTTPS for all API calls
- No logging of sensitive data
- Privacy-respecting queries (no PII sent)
- Rate limiting to respect service ToS

## References

- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [VirusTotal API](https://developers.virustotal.com/)
- [MaxMind GeoIP](https://dev.maxmind.com/geoip)
- [WHOIS Protocol RFC 3912](https://tools.ietf.org/html/rfc3912)
- [PhishTank API](https://www.phishtank.com/api_info.php)
- [URLhaus API](https://urlhaus-api.abuse.ch/)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
