# EML Parser - Feature Specification

## Overview

**Feature Name:** EML Parser
**Module:** emlAnalysis
**Status:** Implemented
**Version:** 1.0.0
**Last Updated:** 2025-11-18

## Purpose

The EML Parser is a command-line tool for analyzing email files (.eml format) to extract metadata, headers, attachments, and threat indicators. It's designed for security analysts investigating phishing emails, malware delivery, and email-based attacks.

## User Stories

### Primary Use Cases

1. **As a SOC Analyst**, I want to quickly analyze a suspicious email to identify the sender's IP address and mail servers used in delivery
2. **As an Incident Responder**, I need to extract all attachments from a phishing email and check their hashes against VirusTotal
3. **As a Threat Hunter**, I want to examine email authentication results (SPF/DKIM/DMARC) to detect spoofing attempts
4. **As a Security Investigator**, I need to extract all URLs and domains from an email body to identify potential phishing sites

## Functional Requirements

### FR-1: Email File Parsing
- **Description**: Parse .eml files and extract structured data
- **Input**: Path to .eml file
- **Output**: Parsed email object with headers, body, attachments
- **Dependencies**: eml-parser library

### FR-2: Header Extraction
- **Description**: Extract and display key email headers
- **Headers Extracted**:
  - From (sender address)
  - To (recipient addresses)
  - Subject
  - Date
  - Reply-To
  - Return-Path
  - X-Mailer
  - X-Priority
  - X-Originating-IP
  - Message-ID
- **Output Format**: JSON object with header fields

### FR-3: IP Address and Relay Tracking
- **Description**: Extract all IP addresses and mail servers from email headers
- **Data Extracted**:
  - Source IP (likely attacker/sender)
  - All relay IPs (full delivery path)
  - Last relay server (server that delivered to victim)
  - All relay servers
- **Logic**: Parse "Received" headers to reconstruct email delivery path

### FR-4: Email Authentication Results
- **Description**: Extract SPF, DKIM, and DMARC validation results
- **Fields Checked**:
  - Received-SPF header
  - Authentication-Results header (DKIM)
  - Authentication-Results header (DMARC)
- **Output**: Pass/Fail/None status for each authentication method

### FR-5: Attachment Extraction
- **Description**: Extract metadata and hashes for all email attachments
- **Data Extracted**:
  - Filename
  - File size
  - Extension
  - Content-Type
  - Hashes (MD5, SHA1, SHA256, SHA512)
- **No File Writing**: Does not extract actual file contents (metadata only)

### FR-6: VirusTotal Integration
- **Description**: Optional scanning of attachment hashes against VirusTotal
- **Trigger**: `--vt` flag
- **Requirements**: VT_API_KEY environment variable
- **Data Retrieved**:
  - Malicious detection count
  - Suspicious detection count
  - Undetected count
  - VirusTotal permalink
- **Rate Limiting**: Respects VT API limits (15 second timeout)

### FR-7: Body Content Extraction
- **Description**: Extract email body content with metadata
- **Data Extracted**:
  - Content-Type (text/plain, text/html)
  - Body hash
  - URI hashes (from links in body)
  - Email hashes (from email addresses in body)
  - Domain hashes
  - Body text preview (first 500 characters)

### FR-8: JSON Output
- **Description**: Output all analysis results as structured JSON
- **Format**: Pretty-printed JSON with 2-space indentation
- **DateTime Handling**: ISO 8601 format serialization
- **Console Output**: Always printed to stdout

### FR-9: File Export
- **Description**: Optional export of JSON report to file
- **Trigger**: `--output` or `-o` flag
- **File Format**: JSON
- **Error Handling**: Permission errors handled gracefully

### FR-10: Verbose Mode
- **Description**: Additional logging for debugging and monitoring
- **Trigger**: `--verbose` flag
- **Output**: VirusTotal lookup status per attachment hash

## Non-Functional Requirements

### NFR-1: Performance
- Parse typical email (< 1MB) in under 2 seconds
- VT lookups add ~1-2 seconds per attachment
- Memory efficient for emails up to 10MB

### NFR-2: Security
- No execution of email attachments
- Secure API key handling via environment variables
- No sensitive data written to logs
- Input validation for file paths

### NFR-3: Reliability
- Graceful handling of malformed .eml files
- Clear error messages with exit codes
- Timeout protection for API calls (15s)
- Works offline (without VT integration)

### NFR-4: Usability
- Clear command-line interface
- Help documentation via `--help`
- Meaningful error messages
- Self-contained executable

### NFR-5: Maintainability
- Modular function design
- Type hints where applicable
- Clear function separation of concerns
- Inline documentation for complex logic

## Technical Design

### Architecture

```
┌─────────────┐
│  CLI Input  │
│ (argparse)  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ parse_eml() │
│             │
└──────┬──────┘
       │
       ▼
┌──────────────────────────┐
│  Extraction Functions    │
├──────────────────────────┤
│ - extract_basic_headers  │
│ - extract_ips_servers    │
│ - extract_auth_results   │
│ - extract_attachments    │
│ - extract_body           │
└──────┬───────────────────┘
       │
       ▼
┌──────────────────┐       ┌───────────────┐
│ build_summary()  │◄──────│ vt_lookup_    │
│                  │       │ sha256()      │
└──────┬───────────┘       └───────────────┘
       │
       ▼
┌──────────────────┐
│  JSON Output     │
│  (console/file)  │
└──────────────────┘
```

### Data Flow

1. **Input**: User provides .eml file path via CLI
2. **Parsing**: eml-parser library decodes email into Python dict
3. **Extraction**: Individual functions extract specific data types
4. **Enhancement**: Optional VT API calls for attachment hashes
5. **Assembly**: build_summary() combines all extracted data
6. **Output**: JSON printed to console and/or file

### Key Functions

#### `parse_eml(file_path) -> dict`
- Opens and reads .eml file
- Returns parsed email dictionary

#### `extract_basic_headers(parsed) -> dict`
- Extracts standard and extended headers
- Returns header dictionary

#### `extract_ips_and_servers(parsed) -> dict`
- Parses Received headers
- Identifies source IP and relay path
- Returns IP/server information

#### `extract_auth_results(parsed) -> dict`
- Extracts SPF/DKIM/DMARC results
- Returns authentication status

#### `extract_attachments(parsed, vt_enabled, verbose) -> list`
- Iterates through all attachments
- Optionally calls VT API for each hash
- Returns list of attachment metadata

#### `vt_lookup_sha256(sha256, verbose) -> dict`
- Queries VirusTotal API v3
- Returns detection statistics
- Handles rate limiting and errors

#### `extract_body(parsed) -> list`
- Extracts body content and metadata
- Returns list of body sections with hashes

#### `build_summary(...) -> dict`
- Orchestrates all extraction functions
- Returns complete analysis report

## Command-Line Interface

### Syntax

```bash
python emlParser.py <eml_file> [OPTIONS]
```

### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `eml` | string | Yes | Path to .eml file to analyze |

### Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--output` | `-o` | string | Path to output JSON file |
| `--vt` | - | flag | Enable VirusTotal scanning |
| `--verbose` | - | flag | Enable verbose output |
| `--help` | `-h` | flag | Show help message |

### Examples

#### Basic Analysis
```bash
python emlParser.py suspicious_email.eml
```

#### With VirusTotal Scanning
```bash
python emlParser.py phishing.eml --vt
```

#### Export to File
```bash
python emlParser.py malware.eml --vt --output report.json
```

#### Verbose Mode
```bash
python emlParser.py sample.eml --vt --verbose
```

## Output Schema

### JSON Structure

```json
{
  "File": "path/to/email.eml",
  "Headers": {
    "From": "sender@example.com",
    "To": ["recipient@example.com"],
    "Subject": "Email subject",
    "Date": "2025-11-18T10:00:00",
    "Reply-To": ["reply@example.com"],
    "Return-Path": ["bounce@example.com"],
    "X-Mailer": ["Mail Client 1.0"],
    "X-Priority": ["3"],
    "X-Originating-IP": ["192.0.2.1"],
    "Message-ID": ["<unique-id@example.com>"]
  },
  "Source IP (likely attacker)": "192.0.2.1",
  "Mail Server that Relayed to Victim": {
    "IP": "203.0.113.5",
    "Server": "mail.example.com"
  },
  "All Relay IPs": ["192.0.2.1", "198.51.100.3", "203.0.113.5"],
  "All Relay Servers": ["mail1.example.com", "mail2.example.com"],
  "SPF/DKIM/DMARC Results": {
    "SPF": "pass",
    "DKIM": "pass",
    "DMARC": "pass"
  },
  "Potentially Phishing Domains Found in URLs": [],
  "Attachments": [
    {
      "filename": "document.pdf",
      "size": 45632,
      "extension": "pdf",
      "content_type": "application/pdf",
      "hashes": {
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706...",
        "sha512": "..."
      },
      "VirusTotal": {
        "VT_Malicious": 0,
        "VT_Suspicious": 0,
        "VT_Undetected": 65,
        "VT_Link": "https://www.virustotal.com/gui/file/2c26b..."
      }
    }
  ],
  "Body Content": [
    {
      "content_type": "text/plain",
      "hash": "body_hash_value",
      "uri_hashes": ["url_hash1", "url_hash2"],
      "email_hashes": ["email_hash1"],
      "domain_hashes": ["domain_hash1"],
      "body_text": "First 500 characters of body..."
    }
  ]
}
```

## Error Handling

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | File not found, parsing error, or VT key missing |

### Error Scenarios

1. **File Not Found**
   - Message: `[INFO] File not found: <path>`
   - Exit Code: 1

2. **VT Key Missing**
   - Message: `[INFO] VirusTotal lookup requested but VT_API_KEY not found in .env`
   - Exit Code: 1

3. **Parsing Error**
   - Message: `[ERROR] Error: <exception message>`
   - Exit Code: 1

4. **VT API Error**
   - Adds to output: `{"VT_Error": "HTTP 404"}` or `{"VT_Error": "<exception>"}`
   - Does not halt execution

## Dependencies

### Python Version
- Python 3.8+

### Required Libraries
```
eml-parser>=1.17.0
requests>=2.31.0
python-dotenv>=1.0.0
```

### Optional
- VirusTotal API key (free tier supports 4 requests/minute)

## Configuration

### Environment Variables

Create `.env` file in project root:

```env
VT_API_KEY=your_virustotal_api_key_here
```

### .env Security
- Must be in `.gitignore`
- Never commit to repository
- Use read-only file permissions (chmod 600)

## Testing

### Test Cases

1. **TC-1: Parse Valid Email**
   - Input: Well-formed .eml file
   - Expected: Complete JSON output with all fields

2. **TC-2: Parse Email with Attachments**
   - Input: .eml with multiple attachments
   - Expected: All attachments listed with hashes

3. **TC-3: VT Lookup**
   - Input: Email with attachment, --vt flag
   - Expected: VT data in attachment objects

4. **TC-4: Missing File**
   - Input: Non-existent file path
   - Expected: Error message and exit code 1

5. **TC-5: Malformed Email**
   - Input: Invalid .eml format
   - Expected: Graceful error handling

6. **TC-6: Output to File**
   - Input: --output flag with path
   - Expected: JSON file created with report

### Test Data

Sample .eml files for testing:
- Clean legitimate email
- Phishing email (sanitized)
- Email with multiple attachments
- Email with HTML body
- Malformed email

## Future Enhancements

### Planned Features

1. **URL Extraction**
   - Parse all URLs from body
   - Check against phishing databases
   - Implement phishing domain detection

2. **Batch Processing**
   - Analyze multiple .eml files
   - Generate summary report
   - Export to CSV

3. **Enhanced Threat Intelligence**
   - Multiple TI sources (AbuseIPDB, URLhaus)
   - IP reputation checks
   - Domain age and registration data

4. **YARA Rules**
   - Scan attachments with YARA rules
   - Detect common malware patterns

5. **Regex IOC Extraction**
   - Extract IPs, domains, hashes from body
   - Standardized IOC output format

6. **HTML Rendering Analysis**
   - Render HTML emails safely
   - Screenshot generation
   - Hidden element detection

## Known Limitations

1. **Large Emails**: May be slow with emails > 10MB
2. **Nested Emails**: Attached .eml files not recursively parsed
3. **Encoded Content**: Some encoding schemes may not decode properly
4. **VT Rate Limits**: Free API limited to 4 requests/minute
5. **Phishing Detection**: Currently placeholder (not implemented)

## Security Considerations

### Threat Model

- **Malicious Attachments**: Tool does not execute or extract files, only analyzes metadata
- **XXE Attacks**: eml-parser library handles XML safely
- **Path Traversal**: Input paths validated and expanded
- **API Key Exposure**: Keys stored in .env, never logged

### Safe Handling

- Run in isolated environment when analyzing malware
- Do not execute extracted attachments
- Validate all file paths before access
- Use API keys with minimal permissions

## Maintenance

### Update Schedule
- Security patches: As needed
- Feature updates: Quarterly
- Dependency updates: Monthly check

### Monitoring
- VT API quota usage
- Error rates
- Performance metrics

## Documentation

### User Documentation
- README.md with usage examples
- Inline help via `--help`
- Example output samples

### Developer Documentation
- Inline code comments
- Function docstrings
- This specification document

## References

- [eml-parser Documentation](https://pypi.org/project/eml-parser/)
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)
- [SPF/DKIM/DMARC Best Practices](https://www.m3aawg.org/authentication)

---

**Specification Author:** Vligai
**Last Review:** 2025-11-18
**Next Review:** 2026-02-18
