# SecOps Helper

A collection of security operations tools to streamline and automate everyday security analyst tasks.

## Overview

SecOps Helper provides command-line utilities for threat analysis, incident response, and security investigations. Each tool is designed to be simple, fast, and effective for SOC analysts and security researchers.

## Available Tools

### EML Parser

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

## Configuration

Create a `.env` file in the project root for API keys:

```env
VT_API_KEY=your_virustotal_api_key
```

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
- [EML Parser Spec](openspec/specs/eml-parser.spec.md) - Detailed EML Parser feature specification

## Roadmap

- [x] EML Parser with VirusTotal integration
- [ ] IOC Extractor (IPs, domains, hashes, URLs)
- [ ] Hash Lookup utility
- [ ] Log Analysis tools
- [ ] Domain/IP Intelligence
- [ ] PCAP Network Traffic Analyzer

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Security

This tool is designed for security analysis. Always handle malicious samples in isolated environments. Never execute extracted attachments or suspicious code.