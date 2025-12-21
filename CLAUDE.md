# CLAUDE.md - AI Assistant Guide for SecOps Helper

This document provides comprehensive guidance for AI assistants working with the SecOps Helper codebase.

## Project Overview

**SecOps Helper** is a collection of security operations tools designed to streamline and automate everyday security analyst tasks. The project provides command-line utilities for threat analysis, incident response, and security investigations.

**Target Users:** SOC Analysts, Incident Responders, Threat Intelligence Analysts, Security Researchers

**Design Philosophy:**
- **Modularity**: Each tool is self-contained and can run independently
- **CLI-First**: All tools accessible via command-line with clear arguments
- **Security-First**: No sensitive data logging, secure API key handling
- **Minimal Dependencies**: Use standard libraries where possible
- **JSON Output**: Structured output for easy parsing and integration

## Repository Structure

```
secops-helper/
├── .env                    # API keys and configuration (gitignored)
├── .gitignore             # Git ignore rules
├── LICENSE                # MIT License
├── README.md              # User-facing documentation
├── requirements.txt       # Python dependencies
├── CLAUDE.md              # This file - AI assistant guide
│
├── secops                 # 🆕 Central control system shell wrapper
├── secops.py              # 🆕 Central control system (Python)
├── secops_helper.py       # Legacy unified CLI (still supported)
│
├── openspec/              # Project specifications (OpenSpec format)
│   ├── project.openspec.md           # Overall project spec
│   └── specs/                        # Individual feature specs
│       ├── eml-parser.spec.md
│       ├── ioc-extractor.spec.md
│       ├── hash-lookup.spec.md
│       ├── domain-ip-intel.spec.md
│       ├── log-analysis.spec.md
│       ├── pcap-analyzer.spec.md
│       ├── yara-scanner.spec.md
│       ├── cert-analyzer.spec.md
│       ├── deobfuscator.spec.md
│       ├── threat-feed-aggregator.spec.md
│       └── file-carver.spec.md
│
├── emlAnalysis/           # Email analysis tools
│   └── emlParser.py       # ✅ IMPLEMENTED
│
├── iocExtractor/          # IOC extraction tools
│   └── extractor.py       # ✅ IMPLEMENTED
│
├── hashLookup/            # Hash threat intelligence
│   └── lookup.py          # ✅ IMPLEMENTED
│
├── domainIpIntel/         # Domain/IP intelligence
│   └── intel.py           # ✅ IMPLEMENTED
│
├── logAnalysis/           # Log analysis tools
│   └── analyzer.py        # ✅ IMPLEMENTED
│
├── pcapAnalyzer/          # Network traffic analysis
│   └── analyzer.py        # ✅ IMPLEMENTED
│
├── urlAnalyzer/           # URL threat analysis
│   └── analyzer.py        # ✅ IMPLEMENTED
│
├── yaraScanner/           # YARA malware scanning
│   ├── scanner.py         # ✅ IMPLEMENTED
│   └── rules/             # YARA rule repository
│       ├── malware/       # Malware detection rules
│       └── apt/           # APT indicators
│
├── certAnalyzer/          # Certificate analysis
│   └── analyzer.py        # ✅ IMPLEMENTED
│
├── deobfuscator/          # Script deobfuscation
│   └── deobfuscator.py    # ✅ IMPLEMENTED
│
├── threatFeedAggregator/  # Threat intelligence aggregation
│   └── aggregator.py      # ✅ IMPLEMENTED
│
└── fileCarver/            # Forensic file extraction
    └── carver.py          # ✅ IMPLEMENTED
```

## Implementation Status

### ✅ Phase 1 (Completed)
- **EML Parser** (`emlAnalysis/emlParser.py`)
  - Email metadata extraction
  - Header analysis (SPF/DKIM/DMARC)
  - Attachment hashing
  - VirusTotal integration

### ✅ Phase 2 (Completed)
- **IOC Extractor** (`iocExtractor/extractor.py`)
  - Extract IPs, domains, URLs, emails, hashes, CVEs
  - Defang/refang capabilities
  - Multiple output formats

- **Hash Lookup** (`hashLookup/lookup.py`)
  - Multi-source threat intelligence (VT, MalwareBazaar)
  - SQLite caching
  - Rate limiting
  - Batch processing

- **Domain/IP Intelligence** (`domainIpIntel/intel.py`)
  - DNS resolution
  - Threat intelligence (VT, AbuseIPDB)
  - Risk scoring
  - Auto IP/domain detection

### ✅ Phase 3 (Completed)
- **Log Analysis** (`logAnalysis/analyzer.py`)
  - Apache/Nginx log parsing
  - Syslog parsing
  - Web attack detection (SQL injection, XSS, path traversal)
  - Brute-force detection
  - Scanner detection
  - Traffic statistics

- **PCAP Analyzer** (`pcapAnalyzer/analyzer.py`)
  - PCAP/PCAPNG file parsing
  - Protocol analysis (TCP, UDP, DNS)
  - Traffic statistics
  - Port scan detection
  - DNS threat detection (DGA, suspicious TLDs)
  - HTTP payload inspection

- **URL Analyzer** (`urlAnalyzer/analyzer.py`)
  - Multi-source threat intelligence (VirusTotal, URLhaus)
  - Suspicious pattern detection (11 different checks)
  - Redis caching with 24-hour TTL
  - Risk scoring and verdict classification
  - Multiple output formats

### ✅ Phase 4 (Completed)
- **YARA Scanner** (`yaraScanner/scanner.py`)
  - Multi-format scanning (files, directories, PCAP, memory dumps)
  - Rule validation and compilation
  - Batch scanning with multi-threading
  - Severity classification (critical/high/medium/low)
  - Match analysis with detailed metadata
  - Integrated with unified CLI

- **Certificate Analyzer** (`certAnalyzer/analyzer.py`)
  - Certificate retrieval from HTTPS servers and files
  - Comprehensive information extraction
  - Chain validation and hostname verification
  - Security issue detection (weak crypto, small keys, expired certs)
  - Phishing detection (brand impersonation, suspicious patterns)
  - Certificate Transparency log queries
  - Risk scoring and verdict classification

- **Deobfuscator** (`deobfuscator/deobfuscator.py`)
  - Multi-language support (JavaScript, PowerShell, VBScript, Batch, Python)
  - Auto-detect script language
  - Multi-layer deobfuscation (up to 10 layers)
  - Encoding detection and decoding (Base64, Hex, URL, ROT13)
  - PowerShell-specific: -EncodedCommand, backtick removal, compression
  - JavaScript-specific: String.fromCharCode(), escape sequences
  - Automatic IOC extraction from deobfuscated code

- **Threat Feed Aggregator** (`threatFeedAggregator/aggregator.py`)
  - Multi-source threat intelligence (ThreatFox, URLhaus)
  - SQLite storage backend with full schema
  - Automatic deduplication by IOC hash
  - Confidence scoring (increases with multiple sources)
  - Search capabilities (by value, type, malware family, confidence)
  - Export to JSON and CSV
  - Statistics and metrics dashboard

- **File Carver** (`fileCarver/carver.py`)
  - Extract files from disk images, memory dumps, binary files
  - 25+ file type signatures (images, documents, archives, executables)
  - Magic bytes detection (headers and footers)
  - Automatic hash calculation (MD5, SHA256)
  - Organized output by file type
  - Chunked processing for large files

## Central Control System (NEW!)

The **SecOps Helper Central Control System** (`secops.py` and `secops` shell wrapper) provides a unified interface for discovering, managing, and executing all 12 security tools.

### Key Features

1. **Automatic Tool Discovery**
   - Scans repository structure and catalogs all available tools
   - Verifies tool availability and reports status
   - Dynamically loads tool modules on demand

2. **Interactive Menu System**
   - User-friendly text-based interface
   - Browse tools by category (Email, Malware, Network, etc.)
   - Search tools by keywords
   - View detailed tool information
   - Check API key configuration status

3. **Smart Search**
   - Search across tool names, descriptions, and keywords
   - Returns relevant tools with category and status
   - Example: `./secops search malware` finds YARA Scanner, Deobfuscator, and related tools

4. **Unified Documentation**
   - Built-in help for every tool
   - Usage examples included
   - API key requirements clearly displayed
   - Quick start guide accessible from menu

5. **Command-Line Interface**
   ```bash
   ./secops                    # Launch interactive menu
   ./secops list               # List all tools with categories
   ./secops info <tool>        # Show detailed tool information
   ./secops search <keyword>   # Search for tools
   ./secops <tool> [args]      # Run a tool directly
   ./secops --version          # Show version information
   ```

### Architecture

The central control system uses a modular architecture:

```
secops (shell wrapper)
  └── secops.py (main control system)
      ├── ToolDiscovery     # Auto-discover and catalog tools
      ├── ToolManager       # Dynamic module loading and execution
      └── InteractiveMenu   # User interface and navigation
```

**ToolDiscovery Class:**
- Maintains metadata for all 12 tools
- Verifies file existence and availability
- Organizes tools by category
- Provides search and filtering capabilities

**ToolManager Class:**
- Dynamically imports tool modules using `importlib`
- Reconstructs command-line arguments for each tool
- Handles errors gracefully with clear messages

**InteractiveMenu Class:**
- Displays categorized tool listings
- Provides search interface
- Shows API key configuration status
- Includes quick start guide

### Tool Categories

The central system organizes tools into 7 categories:

1. **Email Analysis**: EML Parser
2. **Threat Intelligence**: IOC Extractor, Hash Lookup, Domain/IP Intel, URL Analyzer, Threat Feed Aggregator
3. **Log Analysis**: Log Analyzer
4. **Network Analysis**: PCAP Analyzer
5. **SSL/TLS Analysis**: Certificate Analyzer
6. **Malware Analysis**: YARA Scanner, Script Deobfuscator
7. **Forensics**: File Carver

### Usage Examples

```bash
# Interactive mode - recommended for exploration
./secops

# List all tools with status indicators
./secops list

# Search for tools related to malware
./secops search malware
# Returns: YARA Scanner, Deobfuscator, Hash Lookup

# Get detailed information about a tool
./secops info hash
# Shows: Description, examples, API requirements, keywords

# Run tools directly through the control system
./secops eml suspicious.eml --vt
./secops hash 44d88612fea8a8f36de82e1278abb02f
./secops yara scan /samples/ --rules ./yaraScanner/rules/
./secops cert https://example.com
```

### Why Use the Central Control System?

**Benefits over direct tool execution:**
- ✅ **Discoverability**: Easily find the right tool for your task
- ✅ **Documentation**: Built-in help and examples
- ✅ **Consistency**: Uniform interface across all tools
- ✅ **Efficiency**: No need to remember paths or command syntax
- ✅ **Validation**: Check API key status before running tools
- ✅ **Flexibility**: Interactive mode for exploration, CLI for automation

**When to recommend it:**
- User is new to SecOps Helper
- User is unsure which tool to use
- User wants to explore available capabilities
- User needs to check tool availability or API configuration

**Legacy options still supported:**
- Direct tool execution: `python hashLookup/lookup.py <hash>`
- Unified CLI: `python secops_helper.py hash <hash>`

## Code Conventions

### File Structure

Each tool follows this pattern:
```python
#!/usr/bin/env python3
"""
Tool Name - Brief description
Additional context about the tool
"""

import sys
import json
import argparse
# ... other imports

# Classes and functions
class ToolClass:
    """Main tool class"""
    pass

# Helper functions
def parse_args():
    """Parse command-line arguments"""
    pass

def main():
    """Main entry point"""
    pass

if __name__ == '__main__':
    main()
```

### Naming Conventions

- **Files**: `toolName.py` or `analyzer.py` (lowercase, descriptive)
- **Classes**: `PascalCase` (e.g., `IOCExtractor`, `HashValidator`)
- **Functions**: `snake_case` (e.g., `extract_from_text`, `parse_args`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `PATTERNS`, `API_BASE_URL`)
- **Private methods**: `_leading_underscore` (e.g., `_is_private_ip`)

### Command-Line Interface Pattern

All tools must follow this standard CLI pattern:

```python
def parse_args():
    parser = argparse.ArgumentParser(
        description='Tool Name - Brief description',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Example 1
  python tool.py input.txt

  # Example 2
  python tool.py --file input.txt --output results.json
        '''
    )

    parser.add_argument('input', nargs='?', help='Input file or data')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'txt'],
                        default='json', help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')

    return parser.parse_args()
```

### Output Format Standards

#### JSON Output Structure
```python
{
    "metadata": {
        "tool": "tool_name",
        "version": "1.0.0",
        "execution_date": "2025-11-18T10:00:00Z",
        "source": "input_file.txt"
    },
    "summary": {
        "total_items": 10,
        "key_metric": 5
    },
    "results": [
        # ... results array
    ]
}
```

#### CSV Output
- Always include headers
- Escape commas and quotes properly
- Use standard field names

#### Error Handling
```python
# Always exit with proper codes
sys.exit(0)  # Success
sys.exit(1)  # Error

# Always provide clear error messages
print(f"Error: {error_message}", file=sys.stderr)

# Use try-except for external operations
try:
    response = requests.get(url, timeout=15)
except Exception as e:
    return {'error': str(e)}
```

### API Integration Standards

#### Environment Variables
```python
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv('API_KEY_NAME')

# Always check for API key presence
if not API_KEY:
    print("Warning: API_KEY_NAME not set. Feature will be disabled.",
          file=sys.stderr)
```

#### Rate Limiting
```python
class RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.interval = 60.0 / requests_per_minute
        self.last_request = 0

    def wait(self):
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_request = time.time()
```

#### Caching Pattern
```python
class CacheManager:
    def __init__(self, cache_path: str, ttl: int = 86400):
        self.cache_path = cache_path
        self.ttl = ttl  # Time-to-live in seconds
        self._init_db()

    def get(self, key: str) -> Optional[Dict]:
        # Check cache, return None if expired/missing
        pass

    def set(self, key: str, value: Dict):
        # Store with timestamp
        pass
```

## Development Workflow

### Adding a New Tool

1. **Create Specification** (in `openspec/specs/`)
   - Follow the OpenSpec format
   - Include 15 functional requirements (FR-1 to FR-15)
   - Include 5 non-functional requirements
   - Define technical architecture
   - Document CLI interface with examples
   - Include output schemas

2. **Create Directory Structure**
   ```bash
   mkdir -p toolName/
   ```

3. **Implement Core Functionality**
   - Start with main class
   - Add validation functions
   - Implement core logic
   - Add CLI interface
   - Add output formatters

4. **Update Dependencies**
   ```bash
   # Add to requirements.txt with comments
   # Tool Name
   library-name>=version
   ```

5. **Update README.md**
   - Add tool to "Available Tools" section
   - Include usage examples
   - Document API keys if needed

6. **Test the Tool**
   - Manual testing with various inputs
   - Edge cases (empty input, invalid data)
   - Error conditions

7. **Make Executable**
   ```bash
   chmod +x toolName/tool.py
   ```

8. **Git Workflow**
   ```bash
   git add toolName/ README.md requirements.txt
   git commit -m "Implement [Tool Name] with [key features]"
   git push
   ```

### Specification-Driven Development

**CRITICAL:** Always implement tools based on their OpenSpec specifications in `openspec/specs/`. The specs define:

- Functional Requirements (FR-1 through FR-15)
- Non-Functional Requirements (performance, security, etc.)
- Technical Design (architecture, data structures)
- CLI Interface (exact arguments and options)
- Output Schemas (JSON, CSV formats)
- Error Handling
- Testing Strategy

Before implementing any tool:
1. Read the corresponding spec in `openspec/specs/`
2. Understand all functional requirements
3. Follow the defined CLI interface exactly
4. Use the specified output formats
5. Implement error handling as documented

### Git Commit Message Format

Follow this pattern for commit messages:

```
[Action] Brief description (50 chars or less)

- Detailed bullet point 1
- Detailed bullet point 2
- Detailed bullet point 3

Technical details:
- Implementation specifics
- API integrations
- Performance considerations

Examples (if applicable):
  command example
```

**Action verbs:** Add, Implement, Update, Fix, Refactor, Document, Remove

**Recent example:**
```
Implement Phase 2 SecOps Helper tools

Implemented three comprehensive security operations tools:

🔍 IOC Extractor (iocExtractor/extractor.py)
- Extract IPs, domains, URLs, emails, file hashes, CVEs
- Defang/refang capabilities for safe sharing
- Multiple output formats: JSON, CSV, plain text

🔐 Hash Lookup (hashLookup/lookup.py)
- Multi-source threat intelligence (VirusTotal, MalwareBazaar)
- SQLite caching with configurable TTL
- Verdict classification and risk scoring

🌐 Domain/IP Intelligence (domainIpIntel/intel.py)
- DNS resolution and threat intelligence
- Risk scoring (0-100) with classification
- Batch processing support
```

## Key Design Patterns

### 1. Validator Pattern
```python
class Validator:
    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
```

### 2. API Client Pattern
```python
class APIClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.example.com'

    def lookup(self, item: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f'{self.base_url}/endpoint/{item}',
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=15
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            return {'error': str(e)}
        return None
```

### 3. Batch Processing Pattern
```python
def process_batch(items: List[str], verbose=False) -> List[Dict]:
    results = []
    total = len(items)

    for i, item in enumerate(items, 1):
        if verbose:
            print(f"[{i}/{total}] Processing {item}...", file=sys.stderr)

        result = process_single(item)
        results.append(result)

    return results
```

### 4. Output Formatter Pattern
```python
def format_output_json(results: List[Dict], metadata: Dict) -> str:
    output = {
        'metadata': metadata,
        'results': results
    }
    return json.dumps(output, indent=2)

def format_output_csv(results: List[Dict]) -> str:
    lines = ['Header1,Header2,Header3']
    for r in results:
        lines.append(f"{r['field1']},{r['field2']},{r['field3']}")
    return '\n'.join(lines)
```

## Security Considerations

### API Key Handling
- ✅ **NEVER** commit `.env` files
- ✅ **ALWAYS** use `os.getenv()` for API keys
- ✅ **NEVER** log API keys
- ✅ Check for key presence before use
- ✅ Provide clear warnings when keys are missing

### Input Validation
- ✅ Validate all user inputs
- ✅ Sanitize file paths (prevent path traversal)
- ✅ Validate hash formats before queries
- ✅ Check IP/domain formats
- ✅ Use timeouts for all network requests (default: 15s)

### Safe File Operations
```python
# Use Path for file operations
from pathlib import Path

file_path = Path(args.input).expanduser()
if not file_path.exists():
    print(f"Error: File not found: {file_path}", file=sys.stderr)
    sys.exit(1)

# Use context managers
with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()
```

### Network Security
```python
# Always use HTTPS
# Always set timeouts
# Handle network errors gracefully

try:
    response = requests.get(
        url,
        headers=headers,
        timeout=15,  # Always set timeout
        verify=True   # Verify SSL certificates
    )
except requests.Timeout:
    return {'error': 'Request timeout'}
except requests.RequestException as e:
    return {'error': str(e)}
```

## Testing Guidelines

### Manual Testing Checklist

For each tool, test:

1. **Valid Input**
   - Normal cases
   - Edge cases (empty, minimal, maximal)
   - Multiple input methods (CLI, file, stdin)

2. **Invalid Input**
   - Malformed data
   - Missing required arguments
   - Invalid file paths
   - Invalid formats

3. **Error Conditions**
   - Network failures
   - API errors (rate limits, auth failures)
   - File I/O errors
   - Large inputs (performance)

4. **Output Formats**
   - JSON validity (use `jq` to validate)
   - CSV format correctness
   - Plain text readability

5. **API Integration**
   - With API keys
   - Without API keys (graceful degradation)
   - Rate limiting behavior
   - Caching behavior

### Example Test Commands

```bash
# Test with valid input
python tool.py valid_input.txt

# Test with invalid input
python tool.py nonexistent.txt

# Test stdin
echo "test data" | python tool.py -

# Test output formats
python tool.py input.txt --format json
python tool.py input.txt --format csv
python tool.py input.txt --format txt

# Test batch processing
python tool.py --file batch_input.txt

# Test verbose mode
python tool.py input.txt --verbose

# Test caching
python tool.py hash1 hash2  # First run (API calls)
python tool.py hash1 hash2  # Second run (cache hits)
```

## Documentation Standards

### Code Documentation

```python
def extract_iocs(text: str, types: Optional[List[str]] = None) -> Dict:
    """
    Extract Indicators of Compromise from text.

    Args:
        text: The text content to analyze
        types: List of IOC types to extract (None = all types)
               Valid types: 'ip', 'domain', 'url', 'email', 'hash', 'cve'

    Returns:
        Dict containing extracted IOCs organized by type:
        {
            'ips': [...],
            'domains': [...],
            'urls': [...],
            ...
        }

    Examples:
        >>> extract_iocs("Contact us at admin@example.com")
        {'emails': ['admin@example.com'], ...}

        >>> extract_iocs(text, types=['ip', 'domain'])
        {'ips': [...], 'domains': [...]}
    """
    pass
```

### OpenSpec Documentation

Each tool must have a corresponding specification in `openspec/specs/` that includes:

1. **Overview** - Purpose, version, status, priority
2. **User Stories** - Primary use cases
3. **Functional Requirements** - FR-1 through FR-15
4. **Non-Functional Requirements** - Performance, security, usability
5. **Technical Design** - Architecture, data structures, algorithms
6. **Command-Line Interface** - Complete syntax and examples
7. **Output Schema** - JSON/CSV formats with examples
8. **Configuration** - Config file format
9. **Dependencies** - Required libraries
10. **Testing** - Test cases
11. **Future Enhancements** - Planned features
12. **References** - Related documentation

## Common Tasks

### Adding a New IOC Type to IOC Extractor

1. Add regex pattern to `PATTERNS` dict:
```python
PATTERNS = {
    'new_type': r'regex_pattern_here',
    # ... existing patterns
}
```

2. Add extraction logic in `extract_from_text()`:
```python
if 'new_type' in types or 'all' in types:
    new_items = set()
    for match in re.finditer(self.PATTERNS['new_type'], text):
        new_items.add(match.group(0))
    results['new_items'] = sorted(list(new_items))
```

3. Update output formatters to include new type
4. Update documentation

### Adding a New Threat Intelligence Source

1. Create API client class:
```python
class NewSourceAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.newsource.com'

    def lookup(self, indicator: str) -> Optional[Dict]:
        # Implementation
        pass
```

2. Initialize in main tool class:
```python
def __init__(self):
    new_source_key = os.getenv('NEWSOURCE_API_KEY')
    self.new_source = NewSourceAPI(new_source_key) if new_source_key else None
```

3. Query in lookup method:
```python
if self.new_source:
    result = self.new_source.lookup(indicator)
    if result:
        results['sources']['newsource'] = result
```

4. Update `.env.example` and documentation

### Adding a New Output Format

1. Create formatter function:
```python
def format_output_newformat(results: List[Dict]) -> str:
    # Implementation
    return formatted_string
```

2. Add to format choices:
```python
parser.add_argument(
    '--format',
    choices=['json', 'csv', 'txt', 'newformat'],
    default='json'
)
```

3. Add to main conditional:
```python
if args.format == 'newformat':
    output = format_output_newformat(results)
```

## Environment Variables Reference

```bash
# .env file structure

# VirusTotal API (free tier: 4 requests/minute)
# Used by: emlParser, hashLookup, domainIpIntel
VT_API_KEY=your_virustotal_api_key

# AbuseIPDB API (free tier available)
# Used by: domainIpIntel
ABUSEIPDB_KEY=your_abuseipdb_api_key

# MalwareBazaar (no key required)
# Used by: hashLookup

# Future APIs (for Phase 3)
# SHODAN_API_KEY=your_shodan_key
# URLHAUS_API_KEY=your_urlhaus_key
```

## Troubleshooting

### Common Issues

1. **Import errors**
   ```bash
   pip install -r requirements.txt
   ```

2. **API key not found**
   ```bash
   # Create .env file
   echo "VT_API_KEY=your_key_here" > .env
   ```

3. **Rate limiting**
   ```bash
   # Adjust rate limit parameter
   python tool.py --rate-limit 4  # VirusTotal free tier
   ```

4. **Permission denied**
   ```bash
   chmod +x tool.py
   ```

5. **JSON decode errors**
   ```bash
   # Validate JSON output
   python tool.py input.txt | jq .
   ```

## Helpful Commands

```bash
# Format Python code
black tool.py

# Check for common issues
pylint tool.py

# Test JSON output validity
python tool.py test.txt --format json | jq .

# Count lines of code
find . -name "*.py" -exec wc -l {} + | tail -1

# Find all TODOs
grep -r "TODO" --include="*.py"

# Test all tools quickly
for tool in emlAnalysis hashLookup iocExtractor domainIpIntel; do
    echo "Testing $tool..."
    python $tool/*.py --help
done
```

## Future Development

### Enhancement Ideas

- Web dashboard (Flask/FastAPI)
- STIX 2.1 export for all tools
- MISP integration
- Real-time monitoring capabilities
- Machine learning-based anomaly detection
- Docker containers for isolated execution
- CI/CD pipeline with automated testing

## Resources

### External Documentation
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Python argparse](https://docs.python.org/3/library/argparse.html)
- [Regex101](https://regex101.com/) - Test regex patterns

### Internal Documentation
- `openspec/project.openspec.md` - Project overview
- `openspec/specs/*.spec.md` - Individual tool specifications
- `README.md` - User documentation

---

**Last Updated:** 2025-11-20
**Maintained By:** Vligai
**Version:** 3.0.0 (All 12 Tools Complete - Phase 4 Finished)

This document should be updated whenever:
- New tools are added
- Development patterns change
- New conventions are established
- Project structure evolves
