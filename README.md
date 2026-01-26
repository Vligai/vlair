# SecOps Helper

A unified security operations toolkit for threat analysis, incident response, and security investigations.

SecOps Helper brings 12 specialized security tools under a single `secops` command with smart auto-detection, pre-built investigation workflows, and actionable output.

## Installation

```bash
git clone https://github.com/Vligai/secops-helper.git
cd secops-helper
pip install -e .
```

Or with optional dependencies:

```bash
pip install -e ".[all]"      # All features (YARA, PCAP, Redis, etc.)
pip install -e ".[dev]"      # Development tools (pytest, black, etc.)
```

Optional: configure API keys for threat intelligence lookups.

```bash
cp .env.example .env
# Edit .env with your API keys (see Configuration below)
```

## Usage

### Analyze (auto-detect input type)

The primary command. Automatically identifies what you're analyzing and runs the appropriate tools.

```bash
secops analyze suspicious.eml                           # Email
secops analyze 44d88612fea8a8f36de82e1278abb02f         # Hash
secops analyze malicious.com                            # Domain
secops analyze 192.168.1.1                              # IP
secops analyze http://evil.com/payload                  # URL
secops analyze capture.pcap                             # Network capture
secops analyze access.log                               # Log file
secops analyze malware.js                               # Script
```

Output includes a risk score (0-100), verdict (Clean/Suspicious/Malicious), key findings, and recommended actions.

Flags:
- `--verbose` / `-v` -- detailed output
- `--json` / `-j` -- machine-readable JSON
- `--quiet` / `-q` -- just verdict and score (for scripting)

### Workflows (multi-step investigations)

Pre-built investigation patterns that chain multiple tools together.

```bash
secops workflow phishing-email suspicious.eml      # 7-step phishing investigation
secops workflow malware-triage sample.exe           # 7-step malware analysis
secops workflow ioc-hunt iocs.txt                  # 6-step bulk IOC hunting
secops workflow network-forensics capture.pcap     # 7-step PCAP forensics
secops workflow log-investigation access.log       # 7-step log analysis
```

### Investigate (guided mode)

Interactive Q&A that walks you through an investigation when you're unsure which tool to use.

```bash
secops investigate
```

### Direct tool access

Run any individual tool through the unified interface.

```bash
secops eml suspicious.eml --vt
secops ioc report.txt --format csv
secops hash 44d88612fea8a8f36de82e1278abb02f
secops intel malicious.com
secops log access.log
secops pcap capture.pcap
secops url "http://suspicious.com"
secops yara scan /samples/ --rules ./rules/
secops cert https://example.com
secops deobfuscate malware.js --extract-iocs
secops feeds update
secops carve --image disk.dd --output /carved/
```

### Other commands

```bash
secops list                  # List all tools with status
secops info <tool>           # Detailed tool documentation
secops search <keyword>      # Find tools by keyword
secops status                # API keys, cache stats, recent history
```

## Tools

| Tool | Command | Purpose |
|------|---------|---------|
| EML Parser | `eml` | Email header analysis, SPF/DKIM/DMARC, attachment hashing |
| IOC Extractor | `ioc` | Extract IPs, domains, URLs, hashes, CVEs from text |
| Hash Lookup | `hash` | Query VirusTotal and MalwareBazaar for file hashes |
| Domain/IP Intel | `intel` | DNS, reputation, and threat intelligence for domains/IPs |
| Log Analyzer | `log` | Detect SQL injection, XSS, brute-force in Apache/Nginx/syslog |
| PCAP Analyzer | `pcap` | Network traffic analysis, port scan and DGA detection |
| URL Analyzer | `url` | URL reputation checks, suspicious pattern detection |
| YARA Scanner | `yara` | Malware detection with YARA rules |
| Cert Analyzer | `cert` | SSL/TLS certificate security and phishing checks |
| Deobfuscator | `deobfuscate` | Decode obfuscated JS, PowerShell, VBScript, Batch |
| Threat Feeds | `feeds` | Aggregate IOCs from ThreatFox and URLhaus |
| File Carver | `carve` | Extract embedded files from disk images and memory dumps |

## Configuration

Create a `.env` file in the project root:

```env
# VirusTotal (free tier: 4 req/min)
# Used by: eml, hash, intel, url
VT_API_KEY=your_key

# AbuseIPDB (free tier available)
# Used by: intel
ABUSEIPDB_KEY=your_key

# Redis (optional, falls back to in-memory cache)
REDIS_URL=redis://localhost:6379/0
```

All tools work without API keys but provide limited results.

## Output formats

All commands support multiple output formats:

```bash
secops analyze input.eml                  # Console (human-readable)
secops analyze input.eml --json           # JSON (machine-readable)
secops analyze input.eml --quiet          # Minimal (verdict + score)
secops analyze input.eml --report html    # HTML report file
secops analyze input.eml --report md      # Markdown report file
```

Exit codes for automation: 0 = Clean, 1 = Suspicious, 2 = Malicious, 3 = Error.

## Alternative interfaces

### Docker

```bash
docker build -t secops-helper .
docker run --rm --env-file .env -v $(pwd)/data:/data secops-helper analyze /data/suspicious.eml
```

Or with Docker Compose (includes Redis cache):

```bash
docker-compose up -d
docker-compose run --rm secops-helper analyze /data/suspicious.eml
```

### Web dashboard

A Flask-based web UI is available for browser-based analysis (experimental).

```bash
pip install -r requirements-webapp.txt
# Web dashboard is in development
```

### Legacy CLI

The legacy unified CLI is also available:

```bash
secops-helper hash 44d88612fea8a8f36de82e1278abb02f
secops-helper intel malicious.com
```

## Troubleshooting

**ModuleNotFoundError** -- Install dependencies: `pip install -r requirements.txt`

**API rate limits** -- VirusTotal free tier is 4 req/min. Use `--rate-limit 4` for batch operations.

**YARA not found** -- Install: `pip install yara-python>=4.3.0`

**PCAP permission denied** -- May need elevated privileges for raw packet access.

**Check tool/API status** -- Run `secops status` to verify configuration.

## Contributing

Contributions welcome. See [CLAUDE.md](CLAUDE.md) for development conventions and architecture details.

## License

MIT -- See [LICENSE](LICENSE) for details.
