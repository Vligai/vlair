# PCAP Network Traffic Analyzer - Feature Specification

## Overview

**Feature Name:** PCAP Network Traffic Analyzer
**Module:** pcapAnalyzer
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** Medium
**Target Release:** Phase 3-4

## Purpose

The PCAP Network Traffic Analyzer parses and analyzes packet capture files to identify security threats, suspicious network behavior, and protocol anomalies. It extracts IOCs, reconstructs sessions, detects malware traffic patterns, and generates comprehensive reports for incident response and threat hunting.

## User Stories

### Primary Use Cases

1. **As an Incident Responder**, I want to analyze PCAP files from a compromised system to identify C2 communication and data exfiltration
2. **As a Network Security Analyst**, I need to detect port scanning and network reconnaissance in captured traffic
3. **As a Malware Analyst**, I want to extract files and URLs from PCAP to identify malware payloads and delivery mechanisms
4. **As a Threat Hunter**, I need to identify anomalous DNS queries and suspicious TLS/SSL connections
5. **As a SOC Analyst**, I want to quickly summarize network traffic by protocols, top talkers, and suspicious patterns

## Functional Requirements

### FR-1: PCAP File Parsing
- **Description**: Parse standard packet capture formats
- **Supported Formats**:
  - PCAP (.pcap)
  - PCAPNG (.pcapng)
  - Compressed (.pcap.gz, .pcapng.gz)
- **Protocol Support**:
  - Ethernet, IP, TCP, UDP, ICMP
  - HTTP, HTTPS, DNS, FTP, SMTP, SSH
  - SMB, RDP, Telnet
  - Custom protocols (via plugins)
- **Performance**: Stream processing for large files

### FR-2: Traffic Statistics
- **Description**: Generate comprehensive traffic statistics
- **Metrics**:
  - Total packets, bytes
  - Protocol distribution (TCP, UDP, ICMP, etc.)
  - Top source/destination IPs
  - Top ports (source and destination)
  - Bandwidth usage per IP/protocol
  - Conversation pairs (bidirectional flows)
  - Packet size distribution
  - Time-based traffic patterns
- **Visualization**: ASCII charts and tables

### FR-3: Session Reconstruction
- **Description**: Reconstruct TCP/UDP sessions
- **Features**:
  - TCP stream reassembly
  - Follow TCP conversations
  - Extract session payloads
  - Session timeline
  - Retransmission detection
- **Output**: Session data with metadata

### FR-4: HTTP Analysis
- **Description**: Parse and analyze HTTP traffic
- **Data Extracted**:
  - HTTP methods (GET, POST, etc.)
  - URLs and domains
  - User-Agent strings
  - Request/response headers
  - Response codes
  - Cookies
  - File downloads (with reconstruction)
- **Detections**:
  - Suspicious user agents
  - Large file transfers
  - Unusual HTTP methods
  - Suspicious URLs/paths

### FR-5: DNS Analysis
- **Description**: Analyze DNS queries and responses
- **Data Extracted**:
  - Query domains
  - Query types (A, AAAA, MX, TXT, etc.)
  - Response IPs
  - TTL values
  - DNS servers used
- **Detections**:
  - DNS tunneling (high query frequency, long names)
  - DGA (Domain Generation Algorithm) domains
  - Queries to suspicious TLDs
  - Anomalous query patterns
  - DNS exfiltration attempts

### FR-6: TLS/SSL Analysis
- **Description**: Analyze encrypted traffic metadata
- **Data Extracted**:
  - Server Name Indication (SNI)
  - Certificate details (if in handshake)
  - TLS version
  - Cipher suites
  - Session establishment patterns
- **Detections**:
  - Self-signed certificates
  - Weak cipher suites
  - Unusual TLS versions
  - Certificate validation issues
  - Suspicious SNI values

### FR-7: File Extraction
- **Description**: Extract files from network traffic
- **Supported Protocols**:
  - HTTP file downloads
  - FTP file transfers
  - SMTP attachments
  - SMB file transfers
- **File Metadata**:
  - Filename
  - File size
  - MIME type
  - MD5/SHA256 hashes
  - Source/destination IPs
- **Actions**:
  - Save extracted files
  - Hash all files
  - Optional VirusTotal lookup

### FR-8: Threat Detection
- **Description**: Detect known attack patterns
- **Detection Rules**:
  - Port scanning (SYN scans, NULL scans, etc.)
  - Brute-force attempts (repeated connections)
  - Malware C2 beaconing (periodic connections)
  - Data exfiltration (large outbound transfers)
  - Suspicious protocols on non-standard ports
  - ARP spoofing
  - ICMP tunneling
  - Suspicious DNS patterns
- **Severity Levels**: Critical, High, Medium, Low

### FR-9: IOC Extraction
- **Description**: Extract indicators of compromise
- **IOC Types**:
  - IP addresses (source/dest)
  - Domain names (DNS, SNI, HTTP Host)
  - URLs (HTTP requests)
  - File hashes (extracted files)
  - Email addresses (SMTP)
  - User agents
- **Output**: Deduplicated IOC list
- **Export**: STIX, MISP, JSON, CSV

### FR-10: Malware Traffic Detection
- **Description**: Identify malware communication patterns
- **Patterns**:
  - C2 beaconing (regular intervals)
  - Fast flux DNS
  - HTTP POST to suspicious domains
  - TLS connections with rare certificates
  - Unusual port combinations
  - Encrypted tunnels
- **Integration**: Optional YARA rule matching on payloads

### FR-11: Geolocation Analysis
- **Description**: Map IP addresses to locations
- **Features**:
  - GeoIP lookups for all IPs
  - Geographic distribution summary
  - Identify traffic to/from specific countries
  - Flag connections to high-risk regions
- **Database**: MaxMind GeoLite2

### FR-12: Protocol Anomaly Detection
- **Description**: Detect protocol violations and anomalies
- **Detections**:
  - Malformed packets
  - Protocol on wrong port (e.g., HTTP on port 8443)
  - Unusual packet sizes
  - Abnormal TTL values
  - IP fragmentation attacks
  - TCP flags anomalies
- **Output**: List of anomalies with severity

### FR-13: Timeline Generation
- **Description**: Create traffic timeline
- **Features**:
  - Chronological event listing
  - Filter by protocol/IP/port
  - Highlight suspicious events
  - Time-based aggregation (per second/minute/hour)
- **Output**: Timeline view with key events

### FR-14: Filtering & Search
- **Description**: Advanced packet filtering
- **Filter Syntax**: BPF (Berkeley Packet Filter)
- **Examples**:
  - `tcp port 80`
  - `host 192.168.1.1`
  - `dst net 10.0.0.0/8`
- **Search**: Regex search in packet payloads
- **Output**: Filtered PCAP or results

### FR-15: Report Generation
- **Description**: Generate comprehensive analysis reports
- **Formats**:
  - JSON (detailed, machine-readable)
  - HTML (interactive dashboard)
  - PDF (executive summary)
  - Markdown (documentation)
  - CSV (data export)
- **Sections**:
  - Executive summary
  - Traffic statistics
  - Detected threats
  - IOC list
  - Timeline
  - Recommendations

## Non-Functional Requirements

### NFR-1: Performance
- Process 1GB PCAP in < 10 minutes
- Handle PCAPs up to 100GB (streaming mode)
- Memory usage < 1GB for large files
- Real-time analysis for live capture

### NFR-2: Accuracy
- Correct protocol parsing (99%+ packets)
- Accurate session reconstruction
- Minimal false positives (< 5%)
- Complete file extraction

### NFR-3: Scalability
- Support for multi-GB PCAP files
- Parallel processing where possible
- Chunked processing for memory efficiency
- Progress indicators for long operations

### NFR-4: Usability
- Simple CLI with sensible defaults
- Clear, actionable output
- Verbose mode for debugging
- Help documentation with examples

### NFR-5: Extensibility
- Plugin system for custom protocols
- Custom detection rules (YAML/JSON)
- Integrate with YARA for payload scanning
- API for programmatic use

## Technical Design

### Architecture

```
┌─────────────────┐
│  PCAP Reader    │
│  (pyshark/      │
│   scapy)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Packet Parser  │
│  (Protocol      │
│   Dissection)   │
└────────┬────────┘
         │
         ▼
┌──────────────────────────┐
│  Protocol Analyzers      │
├──────────────────────────┤
│ - TCP/UDP Analyzer       │
│ - HTTP Analyzer          │
│ - DNS Analyzer           │
│ - TLS Analyzer           │
│ - SMB Analyzer           │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────┐
│  Session             │
│  Reconstructor       │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  Threat Detection    │
│  Engine              │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  IOC Extractor       │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  File Extractor      │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  Statistics          │
│  Generator           │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  Report Generator    │
│  (JSON/HTML/PDF)     │
└──────────────────────┘
```

### Core Components

#### PacketAnalyzer
```python
class PacketAnalyzer:
    def analyze_packet(self, packet: Packet) -> PacketInfo:
        """Analyze single packet"""

    def extract_metadata(self, packet: Packet) -> Dict:
        """Extract packet metadata"""
```

#### SessionReconstructor
```python
class SessionReconstructor:
    def add_packet(self, packet: Packet):
        """Add packet to session tracking"""

    def get_sessions(self) -> List[Session]:
        """Return all reconstructed sessions"""

    def extract_payload(self, session_id: str) -> bytes:
        """Extract session payload"""
```

#### ThreatDetector
```python
class ThreatDetector:
    def detect_port_scan(self, packets: List[Packet]) -> List[Alert]:
        """Detect port scanning activity"""

    def detect_c2_beacon(self, sessions: List[Session]) -> List[Alert]:
        """Detect C2 beaconing patterns"""

    def detect_dns_tunneling(self, dns_queries: List[DNSQuery]) -> List[Alert]:
        """Detect DNS tunneling"""
```

### Data Structures

```python
@dataclass
class PacketInfo:
    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: Optional[str]
    payload: bytes

@dataclass
class Session:
    session_id: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_time: datetime
    end_time: datetime
    packets: List[PacketInfo]
    bytes_sent: int
    bytes_received: int
    payload: bytes

@dataclass
class ThreatAlert:
    alert_type: str  # port_scan, c2_beacon, dns_tunneling, etc.
    severity: str  # critical, high, medium, low
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    description: str
    confidence: float
    evidence: List[Dict]
    recommendations: List[str]

@dataclass
class ExtractedFile:
    filename: str
    file_type: str
    size: int
    md5: str
    sha256: str
    source_ip: str
    destination_ip: str
    protocol: str
    timestamp: datetime
    path: str  # saved file path
```

## Command-Line Interface

### Syntax

```bash
python pcapAnalyzer/analyzer.py [PCAP_FILE] [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `pcap_file` | string | Yes | Path to PCAP/PCAPNG file |

### Options

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--output` | `-o` | string | stdout | Output file path |
| `--format` | `-f` | string | json | Output format (json/html/pdf/csv/md) |
| `--filter` | | string | - | BPF filter expression |
| `--extract-files` | | flag | False | Extract files from traffic |
| `--extract-dir` | | string | ./extracted | Directory for extracted files |
| `--hash-files` | | flag | True | Hash extracted files |
| `--vt-lookup` | | flag | False | VirusTotal lookup for file hashes |
| `--detect-threats` | | flag | True | Enable threat detection |
| `--ioc-extract` | | flag | True | Extract IOCs |
| `--ioc-output` | | string | - | Export IOCs to file |
| `--sessions` | | flag | False | Reconstruct TCP sessions |
| `--dns-analysis` | | flag | True | Analyze DNS traffic |
| `--http-analysis` | | flag | True | Analyze HTTP traffic |
| `--tls-analysis` | | flag | True | Analyze TLS traffic |
| `--geoip` | | flag | False | Include GeoIP lookups |
| `--timeline` | | flag | False | Generate timeline |
| `--stats` | | flag | True | Include statistics |
| `--top` | | int | 10 | Number of top items in stats |
| `--verbose` | `-v` | flag | False | Verbose output |
| `--threads` | | int | 4 | Worker threads |

### Examples

#### Basic Analysis
```bash
# Analyze PCAP file
python pcapAnalyzer/analyzer.py capture.pcap

# With BPF filter
python pcapAnalyzer/analyzer.py capture.pcap --filter "tcp port 80"
```

#### File Extraction
```bash
# Extract files from HTTP traffic
python pcapAnalyzer/analyzer.py capture.pcap --extract-files --extract-dir ./files

# Extract and hash files
python pcapAnalyzer/analyzer.py capture.pcap --extract-files --hash-files

# Extract and check VirusTotal
python pcapAnalyzer/analyzer.py capture.pcap --extract-files --vt-lookup
```

#### Protocol-Specific Analysis
```bash
# DNS analysis only
python pcapAnalyzer/analyzer.py capture.pcap --dns-analysis --no-http-analysis --no-tls-analysis

# HTTP analysis with sessions
python pcapAnalyzer/analyzer.py capture.pcap --http-analysis --sessions
```

#### Threat Detection
```bash
# Full threat detection
python pcapAnalyzer/analyzer.py capture.pcap --detect-threats

# Generate IOC list
python pcapAnalyzer/analyzer.py capture.pcap --ioc-extract --ioc-output iocs.json
```

#### Report Generation
```bash
# HTML report
python pcapAnalyzer/analyzer.py capture.pcap -f html -o report.html

# PDF executive report
python pcapAnalyzer/analyzer.py capture.pcap -f pdf -o incident_report.pdf

# Timeline view
python pcapAnalyzer/analyzer.py capture.pcap --timeline -f html -o timeline.html
```

#### Advanced
```bash
# Comprehensive analysis with GeoIP
python pcapAnalyzer/analyzer.py capture.pcap --extract-files --geoip --timeline -f html -o full_report.html

# Filter and analyze specific subnet
python pcapAnalyzer/analyzer.py capture.pcap --filter "net 192.168.1.0/24" --detect-threats
```

## Output Schema

### JSON Format

```json
{
  "metadata": {
    "pcap_file": "capture.pcap",
    "file_size_mb": 256.4,
    "analysis_date": "2025-11-18T10:00:00Z",
    "analysis_duration_seconds": 342,
    "filter_applied": "tcp port 80"
  },
  "summary": {
    "total_packets": 1543298,
    "total_bytes": 268435456,
    "duration_seconds": 3600,
    "unique_src_ips": 234,
    "unique_dst_ips": 567,
    "protocols": {
      "TCP": 1234567,
      "UDP": 234567,
      "ICMP": 74164
    }
  },
  "statistics": {
    "top_source_ips": [
      {"ip": "192.168.1.100", "packets": 45234, "bytes": 15234567},
      {"ip": "10.0.0.50", "packets": 34567, "bytes": 12345678}
    ],
    "top_destination_ips": [
      {"ip": "8.8.8.8", "packets": 78901, "bytes": 2345678},
      {"ip": "1.1.1.1", "packets": 56789, "bytes": 1234567}
    ],
    "top_ports": {
      "80": 123456,
      "443": 234567,
      "53": 45678
    },
    "protocol_distribution": {
      "HTTP": 35.2,
      "HTTPS": 45.8,
      "DNS": 10.5,
      "Other": 8.5
    }
  },
  "threats": [
    {
      "id": "threat_001",
      "type": "port_scan",
      "severity": "high",
      "timestamp": "2025-11-18T08:15:23Z",
      "source_ip": "192.0.2.50",
      "description": "Port scan detected from 192.0.2.50 targeting 192.168.1.0/24",
      "confidence": 0.95,
      "evidence": {
        "scanned_ports": 1024,
        "timespan_seconds": 45,
        "scan_type": "SYN",
        "target_ips": 25
      },
      "recommendations": [
        "Block source IP at firewall",
        "Investigate if any ports were successfully accessed",
        "Check for follow-up attack activity"
      ]
    },
    {
      "id": "threat_002",
      "type": "c2_beacon",
      "severity": "critical",
      "timestamp": "2025-11-18T09:30:00Z",
      "source_ip": "192.168.1.150",
      "destination_ip": "198.51.100.50",
      "description": "Regular beaconing pattern detected",
      "confidence": 0.88,
      "evidence": {
        "beacon_interval_seconds": 60,
        "beacon_count": 120,
        "destination_port": 443,
        "jitter": 0.05
      },
      "recommendations": [
        "Isolate infected host 192.168.1.150",
        "Block C2 server 198.51.100.50",
        "Perform full malware analysis on host"
      ]
    }
  ],
  "http_analysis": {
    "total_requests": 4523,
    "unique_urls": 234,
    "user_agents": {
      "Mozilla/5.0...": 3456,
      "curl/7.68.0": 234,
      "python-requests/2.28.0": 123
    },
    "suspicious_requests": [
      {
        "url": "http://malicious.com/payload.exe",
        "method": "GET",
        "user_agent": "Malware Downloader 1.0",
        "response_code": 200,
        "response_size": 245760,
        "timestamp": "2025-11-18T08:45:00Z",
        "flagged_reason": "Suspicious user agent and executable download"
      }
    ]
  },
  "dns_analysis": {
    "total_queries": 15234,
    "unique_domains": 567,
    "top_queried_domains": [
      {"domain": "google.com", "count": 234},
      {"domain": "cloudflare.com", "count": 123}
    ],
    "suspicious_queries": [
      {
        "domain": "abcdefghijklmnopqrstuvwxyz123456.com",
        "query_type": "A",
        "timestamp": "2025-11-18T10:15:00Z",
        "flagged_reason": "Potential DGA domain"
      }
    ],
    "dns_tunneling_indicators": []
  },
  "extracted_files": [
    {
      "filename": "payload.exe",
      "file_type": "PE32 executable",
      "size": 245760,
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706...",
      "source_ip": "198.51.100.50",
      "destination_ip": "192.168.1.150",
      "protocol": "HTTP",
      "timestamp": "2025-11-18T08:45:00Z",
      "virustotal": {
        "detection_ratio": "45/65",
        "verdict": "malicious",
        "malware_family": "TrickBot"
      }
    }
  ],
  "iocs": {
    "ips": ["192.0.2.50", "198.51.100.50"],
    "domains": ["malicious.com", "c2server.net"],
    "urls": ["http://malicious.com/payload.exe"],
    "file_hashes": {
      "md5": ["5d41402abc4b2a76b9719d911017c592"],
      "sha256": ["2c26b46b68ffc68ff99b453c1d30413413422d706..."]
    }
  },
  "recommendations": [
    "Isolate compromised hosts immediately",
    "Block identified C2 servers at network perimeter",
    "Conduct full forensic analysis on affected systems",
    "Update IDS/IPS signatures",
    "Review and strengthen network segmentation"
  ]
}
```

## Configuration File

### YAML Format (pcap-config.yaml)

```yaml
analysis:
  extract_files: true
  hash_files: true
  reconstruct_sessions: true
  detect_threats: true

detection:
  port_scan:
    enabled: true
    threshold_ports: 20
    timespan_seconds: 60

  c2_beacon:
    enabled: true
    min_beacons: 10
    max_jitter: 0.1

  dns_tunneling:
    enabled: true
    min_subdomain_length: 30
    query_frequency_threshold: 100

  data_exfiltration:
    enabled: true
    large_transfer_mb: 100

file_extraction:
  extract_dir: ./extracted_files
  file_types:
    - exe
    - dll
    - pdf
    - zip
    - jar

threat_intelligence:
  virustotal:
    enabled: false
    api_key: ${VT_API_KEY}

  geoip:
    enabled: false
    database: ~/.geoip/GeoLite2-City.mmdb

output:
  format: json
  include_statistics: true
  include_timeline: false
  top_n: 10

performance:
  threads: 4
  chunk_size: 1000
  streaming: true
```

## Dependencies

### Required Libraries
```
scapy>=2.5.0           # Packet manipulation
pyshark>=0.6           # Wireshark wrapper (alternative)
dpkt>=1.9.8            # Fast packet parsing
python-magic>=0.4.27   # File type detection
```

### Optional
```
geoip2>=4.7.0          # GeoIP lookups
yara-python>=4.3.0     # YARA rule matching
reportlab>=4.0.0       # PDF generation
plotly>=5.17.0         # Interactive visualizations
```

## Testing

### Test Cases

1. **TC-1: Basic PCAP Parsing**
   - Input: Small PCAP file
   - Expected: All packets parsed correctly

2. **TC-2: HTTP File Extraction**
   - Input: PCAP with HTTP file download
   - Expected: File extracted with correct hash

3. **TC-3: Port Scan Detection**
   - Input: PCAP with SYN scan
   - Expected: Alert generated

4. **TC-4: DNS Tunneling Detection**
   - Input: PCAP with DNS tunneling
   - Expected: Tunneling detected

5. **TC-5: Session Reconstruction**
   - Input: PCAP with HTTP conversations
   - Expected: Complete sessions reconstructed

6. **TC-6: Large File Processing**
   - Input: 10GB PCAP file
   - Expected: Processed successfully in streaming mode

7. **TC-7: BPF Filtering**
   - Input: PCAP with --filter "tcp port 80"
   - Expected: Only HTTP traffic analyzed

## Future Enhancements

1. **Real-Time Capture**
   - Live packet capture from interface
   - Real-time threat detection

2. **Deep Packet Inspection**
   - Payload regex matching
   - YARA scanning of payloads

3. **Traffic Replay**
   - Replay captured traffic
   - Traffic simulation

4. **Machine Learning Detection**
   - Anomaly detection models
   - Behavioral analysis

5. **Decryption Support**
   - SSL/TLS decryption with keys
   - Decrypt encrypted tunnels

6. **Visualization**
   - Network topology graphs
   - Traffic flow diagrams
   - Interactive dashboards

## Known Limitations

- Cannot decrypt TLS without private keys
- Large PCAPs require significant processing time
- Some protocols may not be fully parsed
- Memory intensive for session reconstruction

## Security Considerations

- Handle malicious payloads safely
- Extracted files should be sandboxed
- No automatic execution of extracted content
- Secure storage of extracted files

## References

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [BPF Syntax](https://biot.com/capstats/bpf.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [Network Forensics Best Practices](https://www.sans.org/white-papers/)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
