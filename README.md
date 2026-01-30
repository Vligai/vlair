# vlair

[![Tests](https://github.com/Vligai/vlair/actions/workflows/tests.yml/badge.svg)](https://github.com/Vligai/vlair/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A unified security operations toolkit for threat analysis, incident response, and security investigations.

vlair brings 12 specialized security tools under a single `vlair` command with smart auto-detection, pre-built investigation workflows, and actionable output.

## Installation

```bash
git clone https://github.com/Vligai/vlair.git
cd vlair
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
vlairanalyze suspicious.eml                           # Email
vlairanalyze 44d88612fea8a8f36de82e1278abb02f         # Hash
vlairanalyze malicious.com                            # Domain
vlairanalyze 192.168.1.1                              # IP
vlairanalyze http://evil.com/payload                  # URL
vlairanalyze capture.pcap                             # Network capture
vlairanalyze access.log                               # Log file
vlairanalyze malware.js                               # Script
```

Output includes a risk score (0-100), verdict (Clean/Suspicious/Malicious), key findings, and recommended actions.

Flags:
- `--verbose` / `-v` -- detailed output
- `--json` / `-j` -- machine-readable JSON
- `--quiet` / `-q` -- just verdict and score (for scripting)

### Workflows (multi-step investigations)

Pre-built investigation patterns that chain multiple tools together.

```bash
vlairworkflow phishing-email suspicious.eml      # 7-step phishing investigation
vlairworkflow malware-triage sample.exe           # 7-step malware analysis
vlairworkflow ioc-hunt iocs.txt                  # 6-step bulk IOC hunting
vlairworkflow network-forensics capture.pcap     # 7-step PCAP forensics
vlairworkflow log-investigation access.log       # 7-step log analysis
```

### Investigate (guided mode)

Interactive Q&A that walks you through an investigation when you're unsure which tool to use.

```bash
vlairinvestigate
```

### Direct tool access

Run any individual tool through the unified interface.

```bash
vlaireml suspicious.eml --vt
vlairioc report.txt --format csv
vlairhash 44d88612fea8a8f36de82e1278abb02f
vlairintel malicious.com
vlairlog access.log
vlairpcap capture.pcap
vlairurl "http://suspicious.com"
vlairyara scan /samples/ --rules ./rules/
vlaircert https://example.com
vlairdeobfuscate malware.js --extract-iocs
vlairfeeds update
vlaircarve --image disk.dd --output /carved/
```

### Other commands

```bash
vlairlist                  # List all tools with status
vlairinfo <tool>           # Detailed tool documentation
vlairsearch <keyword>      # Find tools by keyword
vlairstatus                # API keys, cache stats, recent history
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
vlairanalyze input.eml                  # Console (human-readable)
vlairanalyze input.eml --json           # JSON (machine-readable)
vlairanalyze input.eml --quiet          # Minimal (verdict + score)
vlairanalyze input.eml --report html    # HTML report file
vlairanalyze input.eml --report md      # Markdown report file
```

Exit codes for automation: 0 = Clean, 1 = Suspicious, 2 = Malicious, 3 = Error.

## Alternative interfaces

### Docker

```bash
docker build -t vlair .
docker run --rm --env-file .env -v $(pwd)/data:/data vlair analyze /data/suspicious.eml
```

Or with Docker Compose (includes Redis cache):

```bash
docker-compose up -d
docker-compose run --rm vlair analyze /data/suspicious.eml
```

### Web dashboard

A Flask-based web UI is available for browser-based analysis (experimental).

```bash
pip install -r requirements-webapp.txt
# Web dashboard is in development
```

## Troubleshooting

**ModuleNotFoundError** -- Install dependencies: `pip install -r requirements.txt`

**API rate limits** -- VirusTotal free tier is 4 req/min. Use `--rate-limit 4` for batch operations.

**YARA not found** -- Install: `pip install yara-python>=4.3.0`

**PCAP permission denied** -- May need elevated privileges for raw packet access.

**Check tool/API status** -- Run `vlair status` to verify configuration.

## Contributing

Contributions welcome. See [CLAUDE.md](CLAUDE.md) for development conventions and architecture details.

## License

MIT -- See [LICENSE](LICENSE) for details.
