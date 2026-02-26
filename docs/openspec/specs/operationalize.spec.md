# Operationalize vlair

**Version:** 1.0.0
**Status:** COMPLETE
**Priority:** Critical
**Branch:** feat/operationalize

## Implementation Status

### Phase 1: Smart Analyze Command - COMPLETE
- [x] `core/detector.py` - Input type auto-detection
- [x] `core/scorer.py` - Risk scoring and verdict calculation
- [x] `core/reporter.py` - Console/JSON/quiet output formatting
- [x] `core/analyzer.py` - Main orchestration engine
- [x] Updated `secops.py` with `analyze` command routing
- [x] Unit tests for all core modules:
  - `tests/test_detector.py` - 35+ tests for input detection
  - `tests/test_scorer.py` - 40+ tests for risk scoring
  - `tests/test_reporter.py` - 30+ tests for output formatting
  - `tests/test_analyzer.py` - 25+ tests for orchestration

### Phase 2: Workflows - COMPLETE
- [x] `core/workflow.py` - Workflow engine (base class, context, registry)
- [x] `workflows/phishing_email.py` - 7-step phishing investigation
- [x] `workflows/malware_triage.py` - 7-step malware analysis
- [x] `workflows/ioc_hunt.py` - 6-step bulk IOC hunting
- [x] `workflows/network_forensics.py` - 7-step PCAP forensics
- [x] `workflows/log_investigation.py` - 7-step log analysis
- [x] Updated `secops.py` with `workflow` command routing
- [x] Unit tests: `tests/test_workflows.py` - 25+ workflow tests

### Phase 3: Interactive Mode - COMPLETE
- [x] `core/interactive.py` - Interactive investigation mode (551 lines)
- [x] Progress bar display with terminal visualization
- [x] Guided investigation menus (6 investigation types)
- [x] Post-analysis actions (export IOCs, view JSON, new investigation)
- [x] Updated `secops.py` with `investigate` command routing
- [x] Unit tests: `tests/test_interactive.py` - 34 tests

### Phase 4: Reports and Polish - COMPLETE
- [x] `core/report_generator.py` - HTML and Markdown report generation
- [x] ReportData dataclass for structured report data
- [x] Self-contained HTML reports with inline CSS (responsive, professional)
- [x] Markdown reports with GFM tables
- [x] Executive summary generation
- [x] CLI integration: `--report [html|markdown|md]` and `--output` flags
- [x] Unit tests: `tests/test_report_generator.py`

### Phase 5: Check Command, Status Dashboard & Completions - COMPLETE
- [x] `core/history.py` - SQLite-based analysis history tracker
- [x] `vlair check` command - Quick indicator lookups (hash/domain/ip/url)
- [x] Enhanced `vlair status` dashboard (API keys, tool availability, cache, history, feeds)
- [x] Shell completion scripts (bash, zsh, PowerShell)
- [x] Analysis history recording for both `analyze` and `check` commands
- [x] Fixed `DomainIPIntelligence` import consistency across codebase
- [x] Fixed `json` module scoping bug in `main()` function
- [x] Unit tests: `tests/test_history.py` - 21 tests
- [x] Unit tests: `tests/test_check_command.py` - 19 tests

---

## Problem Statement

vlair has 12 powerful tools but is too cumbersome for practical use:
- Users must know which tool to run and how to invoke it
- Tools are disconnected - no workflows, no chaining
- Output is raw JSON - not actionable insights
- Too much documentation on main screen
- No guidance on "what should I do with this suspicious file/email/log?"

**Target User:** A SOC analyst who receives a suspicious artifact and needs answers fast.

---

## Design Philosophy

1. **Task-Oriented, Not Tool-Oriented** - Users think "analyze this email" not "run emlParser then iocExtractor then hashLookup"
2. **Smart Defaults** - Auto-detect, auto-run, auto-chain
3. **Actionable Output** - Risk scores, verdicts, recommendations - not just data
4. **Progressive Disclosure** - Simple by default, detailed when needed
5. **Zero Learning Curve** - Works immediately, discoverable features

---

## Core Features

### 1. Smart Analyze Command

**The single most important feature.** One command that:
- Auto-detects input type (email, hash, IP, domain, URL, file, PCAP, log)
- Runs appropriate tool(s) automatically
- Chains related tools (extract IOCs → lookup each IOC)
- Returns a verdict with risk score

```bash
# User doesn't need to know which tool to use
vlair analyze suspicious.eml           # Auto-detects email, runs full workflow
vlair analyze 44d88612fea8a8f36de82e1278abb02f   # Auto-detects hash
vlair analyze malicious.com            # Auto-detects domain
vlair analyze 192.168.1.1              # Auto-detects IP
vlair analyze capture.pcap             # Auto-detects PCAP
vlair analyze access.log               # Auto-detects log file
vlair analyze malware.js               # Auto-detects script, deobfuscates
```

**Output:** A consolidated report with:
- Overall risk score (0-100)
- Verdict (Clean / Suspicious / Malicious / Unknown)
- Key findings (bulleted list)
- Recommended actions
- Detailed results (collapsed by default, expandable)

### 2. Workflows (Pre-built Investigation Patterns)

```bash
vlair workflow phishing-email suspicious.eml
vlair workflow malware-triage sample.exe
vlair workflow ioc-hunt iocs.txt
vlair workflow network-forensics capture.pcap
vlair workflow log-investigation access.log
```

Each workflow:
- Runs multiple tools in sequence
- Passes outputs between tools
- Generates a consolidated report
- Provides risk assessment

**Workflow: phishing-email**
1. Parse email headers (SPF/DKIM/DMARC validation)
2. Extract all IOCs (IPs, domains, URLs, hashes from attachments)
3. Check each hash against threat intelligence
4. Check each domain/IP against reputation services
5. Check each URL for malicious indicators
6. Analyze any certificates (sender domain, URLs)
7. Generate phishing probability score
8. Output: Single report with verdict

**Workflow: malware-triage**
1. Calculate file hash
2. Check hash against threat intelligence
3. Scan with YARA rules
4. If script: attempt deobfuscation
5. Extract IOCs from file content
6. Check extracted IOCs
7. Generate malware risk score
8. Output: Single report with verdict

### 3. Simplified CLI

Replace verbose commands with intuitive shortcuts:

```bash
# Instead of: python hashLookup/lookup.py 44d88612fea8a8f36de82e1278abb02f --verbose --format json
vlair check hash 44d88612fea8a8f36de82e1278abb02f

# Instead of: python domainIpIntel/intel.py malicious.com --format json
vlair check domain malicious.com

# Instead of: python urlAnalyzer/analyzer.py "http://bad.com" --format json
vlair check url "http://bad.com"

# Batch checking
vlair check hashes.txt       # Auto-detects list of hashes
vlair check iocs.txt         # Auto-detects mixed IOC types
```

### 4. Report Generation

```bash
vlair analyze suspicious.eml --report          # Generate HTML report
vlair analyze suspicious.eml --report pdf      # Generate PDF report
vlair analyze suspicious.eml --report markdown # Generate Markdown report
```

Report includes:
- Executive summary (1 paragraph)
- Risk assessment (visual score)
- Timeline of analysis steps
- Detailed findings by category
- IOC table (defanged, exportable)
- Recommendations

### 5. Interactive Investigation Mode

```bash
vlair investigate
```

Guided Q&A:
```
What are you investigating?
  [1] Suspicious email
  [2] Suspicious file/attachment
  [3] Suspicious domain/IP/URL
  [4] Network traffic (PCAP)
  [5] Log files
  [6] I have IOCs to check

> 1

Please provide the email file path:
> /path/to/suspicious.eml

Running phishing email analysis...
[████████████████████████████] 100%

═══════════════════════════════════════════════════════════════
                    ANALYSIS COMPLETE
═══════════════════════════════════════════════════════════════
Risk Score: 85/100 (HIGH)
Verdict: LIKELY PHISHING

Key Findings:
  ✗ SPF check: FAIL (sender domain spoofed)
  ✗ 3 malicious URLs detected (URLhaus match)
  ✗ Attachment hash matches known malware (Emotet)
  ⚠ Sender domain registered 2 days ago
  ✓ DKIM: Valid

Recommended Actions:
  1. Block sender domain at email gateway
  2. Block identified malicious URLs
  3. Search mailboxes for similar messages
  4. Check if any users clicked links

[D]etailed results | [E]xport IOCs | [R]eport | [Q]uit
```

### 6. Quick Status Dashboard

```bash
vlair status
```

Shows:
- API key configuration status (✓/✗ for each)
- Cache statistics (hits, size, age)
- Recent analyses (last 10)
- Threat feed freshness

### 7. Quiet Mode for Automation

```bash
# Returns just the verdict and risk score for scripting
vlair analyze suspicious.eml --quiet
# Output: MALICIOUS 85

# JSON output for pipeline integration
vlair analyze suspicious.eml --json
# Output: {"verdict": "MALICIOUS", "risk_score": 85, ...}

# Exit codes for automation
# 0 = Clean, 1 = Suspicious, 2 = Malicious, 3 = Error
```

---

## Implementation Plan

### Phase 1: Smart Analyze Command (MVP)

**Goal:** Single command that auto-detects and analyzes any input

**Tasks:**
- [ ] Create `analyzer.py` - core orchestration engine
- [ ] Implement input type detection (file type, hash format, IP/domain patterns)
- [ ] Create tool chaining logic
- [ ] Implement consolidated output format
- [ ] Add risk scoring algorithm
- [ ] Update secops.py to route `analyze` command

**Input Detection Logic:**
```python
def detect_input_type(input_str):
    if os.path.isfile(input_str):
        ext = get_extension(input_str)
        if ext == '.eml': return 'email'
        if ext in ['.pcap', '.pcapng']: return 'pcap'
        if ext in ['.log']: return 'log'
        if is_log_format(input_str): return 'log'
        if ext in ['.js', '.ps1', '.vbs', '.bat', '.py']: return 'script'
        return 'file'
    if is_md5(input_str) or is_sha1(input_str) or is_sha256(input_str): return 'hash'
    if is_ipv4(input_str) or is_ipv6(input_str): return 'ip'
    if is_url(input_str): return 'url'
    if is_domain(input_str): return 'domain'
    return 'unknown'
```

### Phase 2: Workflows

**Goal:** Pre-built investigation patterns for common scenarios

**Tasks:**
- [ ] Create workflow engine
- [ ] Implement phishing-email workflow
- [ ] Implement malware-triage workflow
- [ ] Implement ioc-hunt workflow
- [ ] Implement network-forensics workflow
- [ ] Implement log-investigation workflow
- [ ] Add workflow documentation

### Phase 3: Interactive Mode

**Goal:** Guided investigation for users who don't know what they have

**Tasks:**
- [ ] Create interactive prompt system
- [ ] Implement guided workflows
- [ ] Add progress indicators
- [ ] Create formatted output renderer
- [ ] Add investigation history

### Phase 4: Reports and Polish

**Goal:** Professional reports and automation support

**Tasks:**
- [ ] Implement HTML report generation
- [ ] Implement Markdown report generation
- [ ] Add quiet mode for scripting
- [ ] Implement status dashboard
- [ ] Add shell completion scripts

---

## Output Format Specification

### Console Output (Default)

```
═══════════════════════════════════════════════════════════════
 vlair - Analysis Report
═══════════════════════════════════════════════════════════════

Input: suspicious.eml
Type: Email
Analyzed: 2025-01-20 10:30:45 UTC

───────────────────────────────────────────────────────────────
 VERDICT: MALICIOUS                           Risk Score: 85/100
───────────────────────────────────────────────────────────────

Key Findings:
  [!] SPF validation failed - likely spoofed sender
  [!] 3 URLs match known phishing infrastructure
  [!] Attachment hash matches Emotet malware family
  [⚠] Sender domain age: 2 days (suspicious)
  [✓] DKIM signature valid

Extracted IOCs:
  Hashes (1):    44d88612fea8a8f36de82e1278abb02f [MALICIOUS]
  URLs (3):      hxxps://evil[.]com/payload [MALICIOUS]
                 hxxps://phish[.]net/login [MALICIOUS]
                 hxxps://legit[.]com/image.png [CLEAN]
  Domains (2):   evil[.]com [MALICIOUS], phish[.]net [MALICIOUS]
  IPs (1):       192.168.1.1 [SUSPICIOUS]

Recommended Actions:
  1. Block sender domain at email gateway
  2. Block identified malicious URLs at proxy
  3. Search for similar emails in organization
  4. Alert users who received this email
  5. Submit attachment to sandbox for analysis

───────────────────────────────────────────────────────────────
Use --verbose for detailed results | --report for full report
═══════════════════════════════════════════════════════════════
```

### JSON Output (--json)

```json
{
  "input": "suspicious.eml",
  "type": "email",
  "timestamp": "2025-01-20T10:30:45Z",
  "verdict": "MALICIOUS",
  "risk_score": 85,
  "confidence": "HIGH",
  "findings": [
    {"severity": "critical", "message": "SPF validation failed", "details": "..."},
    {"severity": "critical", "message": "URLs match phishing infrastructure", "count": 3},
    {"severity": "critical", "message": "Attachment matches known malware", "family": "Emotet"}
  ],
  "iocs": {
    "hashes": [{"value": "44d88612...", "verdict": "MALICIOUS", "sources": ["VirusTotal"]}],
    "urls": [...],
    "domains": [...],
    "ips": [...]
  },
  "recommendations": [...],
  "tool_results": {
    "eml_parser": {...},
    "ioc_extractor": {...},
    "hash_lookup": {...}
  }
}
```

---

## Risk Scoring Algorithm

```python
def calculate_risk_score(findings):
    score = 0

    # Critical findings (25 points each, max 75)
    critical_count = count_findings(findings, 'critical')
    score += min(critical_count * 25, 75)

    # High findings (10 points each, max 20)
    high_count = count_findings(findings, 'high')
    score += min(high_count * 10, 20)

    # Medium findings (3 points each, max 5)
    medium_count = count_findings(findings, 'medium')
    score += min(medium_count * 3, 5)

    return min(score, 100)

def get_verdict(score):
    if score >= 70: return 'MALICIOUS'
    if score >= 40: return 'SUSPICIOUS'
    if score >= 10: return 'LOW_RISK'
    return 'CLEAN'
```

---

## Files to Create/Modify

### New Files
- `core/analyzer.py` - Main orchestration engine
- `core/detector.py` - Input type detection
- `core/scorer.py` - Risk scoring
- `core/reporter.py` - Report generation
- `core/workflow.py` - Workflow engine
- `workflows/phishing_email.py`
- `workflows/malware_triage.py`
- `workflows/ioc_hunt.py`

### Modify
- `secops.py` - Add analyze command, simplify menu
- `secops` - Update shell wrapper
- `README.md` - Update with new usage
- `CLAUDE.md` - Update development guide

---

## Success Metrics

1. **Time to First Value** - New user can analyze a suspicious file in < 30 seconds
2. **Command Simplicity** - Most analyses require single command
3. **Actionable Output** - Every analysis provides clear next steps
4. **Learning Curve** - No documentation reading required for basic use

---

## Non-Goals (Out of Scope)

- Web UI (future phase)
- Real-time monitoring
- SIEM integration
- Multi-user collaboration
- Cloud deployment

---

## Open Questions

1. Should `vlair analyze` be the default when no subcommand given?
2. How verbose should default output be?
3. Should we persist analysis history to SQLite?
4. What report templates do SOC analysts actually need?

---

## References

- Current tool implementations in respective directories
- Existing OpenSpec specifications in `/openspec/specs/`
- User feedback on tool usability
