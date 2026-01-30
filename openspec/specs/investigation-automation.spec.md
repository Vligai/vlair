# Investigation Automation Specification

**Version:** 1.0.0
**Status:** Draft
**Priority:** High
**Author:** vlair Team
**Created:** 2026-01-28

## Overview

### Problem Statement

Security investigations follow predictable patterns, yet analysts manually execute the same steps hundreds of times:

**Phishing Investigation (typical manual workflow):**
1. Open email in quarantine → 2 min
2. Copy sender, subject, extract attachments → 3 min
3. Check sender domain reputation → 2 min
4. Check attachment hashes on VT → 3 min
5. Extract and check URLs → 5 min
6. Search SIEM for other recipients → 5 min
7. Check if anyone clicked links → 5 min
8. Document findings in ticket → 10 min
9. Decide on remediation → 5 min

**Total: ~40 minutes per phishing report**

With 20+ phishing reports per day, analysts spend 13+ hours on repetitive investigation steps.

### Solution

End-to-end investigation automation that:
1. **Ingests** artifacts directly from source systems (email, EDR, SIEM)
2. **Executes** complete investigation playbooks automatically
3. **Correlates** findings across data sources
4. **Produces** investigation reports with recommendations
5. **Prepares** remediation actions for one-click execution

### Value Proposition

| Investigation Type | Manual Time | Automated Time | Savings |
|-------------------|-------------|----------------|---------|
| Phishing email | 40 min | 3 min | 92% |
| Malware alert | 60 min | 5 min | 92% |
| Suspicious login | 25 min | 2 min | 92% |
| Data exfil alert | 45 min | 4 min | 91% |

## User Stories

### US-1: One-Command Phishing Investigation
> As a SOC analyst, I want to run a single command that fully investigates a phishing report, so I can handle 5x more incidents per shift.

### US-2: Automated Evidence Collection
> As an incident responder, I want automated collection of all relevant artifacts (emails, logs, endpoint data), so I don't miss evidence due to manual oversight.

### US-3: Cross-System Correlation
> As a security analyst, I want the investigation to automatically query all relevant systems (email, SIEM, EDR), so I get a complete picture without switching between 10 consoles.

### US-4: Remediation Preparation
> As a SOC analyst, I want pre-built remediation commands ready to execute, so I can contain threats in seconds rather than minutes.

### US-5: Investigation Audit Trail
> As a SOC manager, I want complete documentation of every investigation step, so we have defensible evidence for legal/compliance.

## Functional Requirements

### FR-1: Investigation Types

Support automated investigations for common security scenarios:

```bash
# Phishing investigation
vlair investigate phishing --email-id MSG123 --source o365
vlair investigate phishing --file suspicious.eml

# Malware investigation
vlair investigate malware --host WORKSTATION01 --alert-id ALT456
vlair investigate malware --hash abc123def456

# Suspicious authentication
vlair investigate auth --user jsmith --timeframe 24h
vlair investigate auth --source-ip 1.2.3.4

# Data exfiltration
vlair investigate exfil --user jsmith --timeframe 7d
vlair investigate exfil --destination evil.com

# Generic IOC hunt
vlair investigate ioc --indicator evil.com --scope enterprise
```

### FR-2: Phishing Investigation Playbook

Fully automated phishing investigation:

```bash
vlair investigate phishing --email-id AAMkAGI2... --source o365

# Automatic steps executed:
# 1. Retrieve email from O365/Gmail via API
# 2. Parse headers, extract sender info
# 3. Check sender domain (age, reputation, SPF/DKIM/DMARC)
# 4. Extract and analyze all attachments
#    - Hash lookup on VT, MalwareBazaar
#    - YARA scan
#    - Macro/script extraction
# 5. Extract and analyze all URLs
#    - Reputation check
#    - Screenshot capture
#    - Redirect chain analysis
# 6. Query SIEM: other recipients of same email
# 7. Query SIEM: users who clicked links
# 8. Query EDR: execution events from attachments
# 9. Correlate with threat intel (campaign attribution)
# 10. Generate investigation report
# 11. Prepare remediation actions
```

**Output:**
```
══════════════════════════════════════════════════════════════════
            PHISHING INVESTIGATION REPORT
══════════════════════════════════════════════════════════════════

VERDICT: MALICIOUS PHISHING CAMPAIGN
SEVERITY: HIGH
CONFIDENCE: 94%

Email Summary:
  Subject: "Urgent: Invoice #38291 Payment Required"
  From: accounting@paypa1.com (SPOOFED)
  Received: 2026-01-28 09:15:23 UTC
  Recipients in org: 47

Sender Analysis:
  Domain: paypa1.com
  Registration: 2026-01-26 (2 days ago) ⚠️
  SPF: FAIL
  DKIM: FAIL
  DMARC: FAIL
  Reputation: MALICIOUS (known phishing infrastructure)

Attachment Analysis:
  Filename: Invoice_38291.xlsm
  Hash: 7d3e8f2a1b4c5d6e...
  VT Detection: 38/68 (Emotet)
  Contains: Malicious VBA macro
  Behavior: Downloads payload from hxxp://evil.com/stage2.exe

URL Analysis:
  URLs found: 2
  - hxxps://paypa1.com/verify (MALICIOUS - credential phishing)
  - hxxps://bit.ly/3xK2mN (redirects to malware download)

Impact Assessment:
  Recipients: 47 users
  Opened email: 12 users
  Clicked links: 3 users ⚠️
    - jsmith (2026-01-28 09:22:14)
    - mjohnson (2026-01-28 09:45:02)
    - klee (2026-01-28 10:01:33)
  Executed attachment: 1 user ⚠️
    - jsmith (2026-01-28 09:23:01)

Remediation Actions (ready to execute):
  [ ] Delete email from all 47 mailboxes
      Command: vlair remediate email-delete --message-id MSG123

  [ ] Block sender domain
      Command: vlair remediate block-domain paypa1.com

  [ ] Isolate compromised host
      Command: vlair remediate isolate-host JSMITH-PC

  [ ] Reset credentials for affected users
      Command: vlair remediate reset-password jsmith mjohnson klee

  [ ] Block malicious URLs at proxy
      Command: vlair remediate block-url hxxps://paypa1.com/verify

Investigation ID: INV-2026-01-28-0042
Duration: 47 seconds
══════════════════════════════════════════════════════════════════
```

### FR-3: Malware Investigation Playbook

```bash
vlair investigate malware --host WORKSTATION01 --alert-id ALT456

# Automatic steps:
# 1. Retrieve alert details from EDR/SIEM
# 2. Identify malicious file (hash, path, process)
# 3. Hash lookup (VT, MalwareBazaar, internal DB)
# 4. Retrieve file sample if available
# 5. Sandbox analysis (if configured)
# 6. Extract IOCs from sample
# 7. Query EDR: process tree, network connections
# 8. Query EDR: persistence mechanisms
# 9. Query SIEM: lateral movement indicators
# 10. Query SIEM: other hosts with same IOCs
# 11. Timeline reconstruction
# 12. Generate report with containment recommendations
```

### FR-4: Authentication Investigation Playbook

```bash
vlair investigate auth --user jsmith --timeframe 24h

# Automatic steps:
# 1. Query IAM: recent authentications for user
# 2. Identify anomalies (new location, new device, impossible travel)
# 3. Query SIEM: authentication logs across all systems
# 4. Query SIEM: activities performed after authentication
# 5. Check source IPs against threat intel
# 6. Check for password spray patterns (same IP, multiple users)
# 7. Query HR system: is user traveling? (if integrated)
# 8. Generate risk assessment
```

### FR-5: Data Source Connectors

Pluggable connectors for enterprise systems:

```yaml
# .secops/connectors.yaml

email:
  provider: microsoft365
  tenant_id: ${M365_TENANT_ID}
  client_id: ${M365_CLIENT_ID}
  client_secret: ${M365_CLIENT_SECRET}

  # Or Gmail
  # provider: google_workspace
  # credentials_file: /path/to/service-account.json

siem:
  provider: splunk
  host: splunk.company.com
  port: 8089
  token: ${SPLUNK_TOKEN}

  # Or Elastic
  # provider: elastic
  # host: elastic.company.com
  # api_key: ${ELASTIC_API_KEY}

edr:
  provider: crowdstrike
  client_id: ${CS_CLIENT_ID}
  client_secret: ${CS_CLIENT_SECRET}

  # Or Microsoft Defender
  # provider: defender
  # tenant_id: ${DEFENDER_TENANT_ID}

identity:
  provider: azure_ad
  tenant_id: ${AAD_TENANT_ID}

  # Or Okta
  # provider: okta
  # domain: company.okta.com
  # token: ${OKTA_TOKEN}
```

### FR-6: Connector Abstraction Layer

```python
from abc import ABC, abstractmethod

class EmailConnector(ABC):
    """Abstract email system connector"""

    @abstractmethod
    def get_message(self, message_id: str) -> Email:
        """Retrieve email by ID"""
        pass

    @abstractmethod
    def search_messages(self, query: str, timeframe: str) -> List[Email]:
        """Search for emails matching criteria"""
        pass

    @abstractmethod
    def get_recipients(self, message_id: str) -> List[str]:
        """Get all recipients of a message"""
        pass

    @abstractmethod
    def delete_message(self, message_id: str, mailboxes: List[str]) -> bool:
        """Delete message from specified mailboxes"""
        pass

class SIEMConnector(ABC):
    """Abstract SIEM connector"""

    @abstractmethod
    def search(self, query: str, timeframe: str) -> List[Dict]:
        """Execute search query"""
        pass

    @abstractmethod
    def get_events_by_host(self, hostname: str, timeframe: str) -> List[Dict]:
        """Get all events for a host"""
        pass

    @abstractmethod
    def get_events_by_user(self, username: str, timeframe: str) -> List[Dict]:
        """Get all events for a user"""
        pass

class EDRConnector(ABC):
    """Abstract EDR connector"""

    @abstractmethod
    def get_host_details(self, hostname: str) -> Host:
        """Get host information"""
        pass

    @abstractmethod
    def get_process_tree(self, host: str, process_id: str) -> ProcessTree:
        """Get process execution tree"""
        pass

    @abstractmethod
    def isolate_host(self, hostname: str) -> bool:
        """Network isolate a host"""
        pass

    @abstractmethod
    def get_file_sample(self, host: str, file_path: str) -> bytes:
        """Retrieve file from endpoint"""
        pass
```

### FR-7: Investigation State Management

Track investigation progress and allow resume:

```bash
# Start investigation (runs in background if long-running)
vlair investigate phishing --email-id MSG123 --background
# Output: Investigation started: INV-2026-01-28-0042

# Check status
vlair investigate status INV-2026-01-28-0042
# Output:
# Status: IN_PROGRESS (65%)
# Current step: Querying SIEM for related events
# Completed: 8/12 steps
# Duration: 32 seconds

# Get results when complete
vlair investigate results INV-2026-01-28-0042

# List recent investigations
vlair investigate list --last 24h

# Resume failed investigation
vlair investigate resume INV-2026-01-28-0042
```

### FR-8: Remediation Actions

Pre-built remediation commands based on investigation findings:

```bash
# Execute single remediation
vlair remediate isolate-host WORKSTATION01

# Execute all recommended remediations
vlair remediate --investigation INV-2026-01-28-0042 --all

# Execute with approval workflow
vlair remediate --investigation INV-2026-01-28-0042 --require-approval

# Dry run (show what would happen)
vlair remediate --investigation INV-2026-01-28-0042 --dry-run
```

**Available Remediation Actions:**

| Action | Description | Systems |
|--------|-------------|---------|
| `isolate-host` | Network isolate endpoint | CrowdStrike, Defender, Carbon Black |
| `disable-user` | Disable AD/Okta account | Azure AD, Okta, On-prem AD |
| `reset-password` | Force password reset | Azure AD, Okta |
| `revoke-sessions` | Terminate all user sessions | Azure AD, Okta, O365 |
| `block-domain` | Add to email block list | O365, Proofpoint, Mimecast |
| `block-url` | Add to proxy block list | Zscaler, Palo Alto |
| `block-hash` | Add to EDR block list | CrowdStrike, Defender |
| `email-delete` | Delete email from mailboxes | O365, Gmail |
| `quarantine-file` | Quarantine file on endpoint | CrowdStrike, Defender |

### FR-9: Evidence Collection and Chain of Custody

Automated evidence preservation:

```bash
vlair investigate malware --host WORKSTATION01 --collect-evidence

# Evidence collected:
# - Memory dump (if configured)
# - Malicious files
# - Relevant logs
# - Process listings
# - Network connections
# - Registry artifacts (Windows)

# Evidence stored with chain of custody:
evidence/
└── INV-2026-01-28-0042/
    ├── manifest.json           # What was collected, when, by whom
    ├── hashes.txt              # SHA256 of all evidence files
    ├── memory_dump.raw.gz
    ├── malware_sample.exe
    ├── process_list.json
    ├── network_connections.json
    ├── event_logs/
    │   ├── security.evtx
    │   └── system.evtx
    └── screenshots/
        └── phishing_page.png
```

### FR-10: Custom Playbook Definition

Allow users to define custom investigation playbooks:

```yaml
# playbooks/custom-insider-threat.yaml
name: Insider Threat Investigation
description: Investigate potential data theft by employee
version: 1.0

inputs:
  - name: username
    type: string
    required: true
  - name: timeframe
    type: duration
    default: 30d

steps:
  - name: Get user profile
    action: identity.get_user
    params:
      username: "{{ inputs.username }}"
    output: user_profile

  - name: Check resignation status
    action: hr.check_status
    params:
      employee_id: "{{ user_profile.employee_id }}"
    output: hr_status

  - name: Get file access logs
    action: siem.search
    params:
      query: |
        index=file_access user="{{ inputs.username }}"
        action IN (download, copy, email_attachment)
      timeframe: "{{ inputs.timeframe }}"
    output: file_access

  - name: Get USB activity
    action: edr.get_usb_events
    params:
      username: "{{ inputs.username }}"
      timeframe: "{{ inputs.timeframe }}"
    output: usb_events

  - name: Get cloud storage uploads
    action: casb.get_uploads
    params:
      username: "{{ inputs.username }}"
      timeframe: "{{ inputs.timeframe }}"
    output: cloud_uploads

  - name: Analyze patterns
    action: ai.analyze
    params:
      context:
        user: "{{ user_profile }}"
        hr_status: "{{ hr_status }}"
        file_access: "{{ file_access }}"
        usb_events: "{{ usb_events }}"
        cloud_uploads: "{{ cloud_uploads }}"
      prompt: "Analyze for insider threat indicators"
    output: analysis

  - name: Generate report
    action: report.generate
    params:
      template: insider_threat
      data:
        analysis: "{{ analysis }}"
        evidence:
          - "{{ file_access }}"
          - "{{ usb_events }}"
          - "{{ cloud_uploads }}"
```

## Technical Design

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Investigation Engine                          │
├─────────────────────────────────────────────────────────────────┤
│  CLI Interface                                                  │
│  vlair investigate <type> [options]                            │
├─────────────────────────────────────────────────────────────────┤
│  Investigation Orchestrator                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Playbook    │  │ Step        │  │ State       │            │
│  │ Engine      │  │ Executor    │  │ Manager     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  Connector Layer                                                │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐      │
│  │ Email  │ │ SIEM   │ │ EDR    │ │ IAM    │ │ Threat │      │
│  │ O365   │ │ Splunk │ │ CS     │ │ AzureAD│ │ Intel  │      │
│  │ Gmail  │ │ Elastic│ │ MDE    │ │ Okta   │ │ VT/MB  │      │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘      │
├─────────────────────────────────────────────────────────────────┤
│  Evidence & Reporting                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Evidence    │  │ Report      │  │ Remediation │            │
│  │ Collector   │  │ Generator   │  │ Engine      │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
src/secops_helper/
├── investigate/
│   ├── __init__.py
│   ├── engine.py              # Main investigation orchestrator
│   ├── playbooks/
│   │   ├── __init__.py
│   │   ├── base.py            # Base playbook class
│   │   ├── phishing.py        # Phishing investigation
│   │   ├── malware.py         # Malware investigation
│   │   ├── auth.py            # Auth anomaly investigation
│   │   └── exfil.py           # Data exfil investigation
│   ├── connectors/
│   │   ├── __init__.py
│   │   ├── base.py            # Abstract connector classes
│   │   ├── email/
│   │   │   ├── microsoft365.py
│   │   │   └── google.py
│   │   ├── siem/
│   │   │   ├── splunk.py
│   │   │   └── elastic.py
│   │   ├── edr/
│   │   │   ├── crowdstrike.py
│   │   │   └── defender.py
│   │   └── identity/
│   │       ├── azure_ad.py
│   │       └── okta.py
│   ├── evidence.py            # Evidence collection
│   ├── remediation.py         # Remediation actions
│   └── state.py               # Investigation state management
```

### Investigation State Schema

```python
@dataclass
class InvestigationState:
    id: str                          # INV-2026-01-28-0042
    type: str                        # phishing, malware, auth, etc.
    status: str                      # pending, running, completed, failed
    created_at: datetime
    updated_at: datetime
    inputs: Dict[str, Any]           # Investigation inputs
    current_step: int
    total_steps: int
    steps: List[StepResult]          # Results from each step
    findings: Dict[str, Any]         # Aggregated findings
    recommendations: List[str]       # Recommended actions
    remediation_actions: List[RemediationAction]
    evidence_path: Optional[str]     # Path to collected evidence
    error: Optional[str]             # Error message if failed

@dataclass
class StepResult:
    name: str
    status: str                      # completed, failed, skipped
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    output: Dict[str, Any]
    error: Optional[str]

@dataclass
class RemediationAction:
    id: str
    name: str
    description: str
    command: str
    status: str                      # pending, approved, executed, failed
    requires_approval: bool
    executed_at: Optional[datetime]
    executed_by: Optional[str]
```

## CLI Interface

### Investigation Commands

```bash
# Phishing investigation
vlair investigate phishing --email-id <id> --source o365|gmail
vlair investigate phishing --file <path.eml>
vlair investigate phishing --url <suspicious-url>

# Malware investigation
vlair investigate malware --host <hostname> --alert-id <id>
vlair investigate malware --hash <sha256>
vlair investigate malware --file <sample.exe>

# Authentication investigation
vlair investigate auth --user <username> [--timeframe 24h]
vlair investigate auth --source-ip <ip> [--timeframe 24h]

# Data exfiltration investigation
vlair investigate exfil --user <username> [--timeframe 7d]
vlair investigate exfil --destination <domain>

# IOC hunt across enterprise
vlair investigate ioc --indicator <ioc> --scope enterprise

# Custom playbook
vlair investigate custom --playbook insider-threat.yaml --username jsmith
```

### Options

```bash
--output, -o         Output format: console, json, markdown, html
--evidence           Collect and preserve evidence
--background         Run investigation in background
--notify             Send notification when complete (email, Slack)
--dry-run            Show what would be investigated without executing
--no-remediation     Skip remediation recommendations
--verbose, -v        Show detailed progress
```

### Management Commands

```bash
# List investigations
vlair investigate list [--last 24h] [--status completed|failed|running]

# Get investigation status
vlair investigate status <investigation-id>

# Get investigation results
vlair investigate results <investigation-id> [--format json|md]

# Resume failed investigation
vlair investigate resume <investigation-id>

# Cancel running investigation
vlair investigate cancel <investigation-id>
```

### Remediation Commands

```bash
# List available remediations for investigation
vlair remediate list --investigation <id>

# Execute specific remediation
vlair remediate <action> [params]
vlair remediate isolate-host WORKSTATION01
vlair remediate block-domain evil.com
vlair remediate reset-password jsmith

# Execute all recommended remediations
vlair remediate --investigation <id> --all

# Execute with approval
vlair remediate --investigation <id> --require-approval

# Dry run
vlair remediate --investigation <id> --dry-run
```

## Non-Functional Requirements

### NFR-1: Performance
- Simple investigations complete in <60 seconds
- Complex investigations complete in <5 minutes
- Background processing for long-running tasks

### NFR-2: Reliability
- Automatic retry for transient failures
- Investigation state persisted (survives crashes)
- Graceful degradation if connectors unavailable

### NFR-3: Security
- Credentials stored securely (encrypted at rest)
- Audit log of all investigation actions
- RBAC for remediation actions
- No sensitive data in logs

### NFR-4: Scalability
- Support concurrent investigations
- Queue management for API rate limits
- Configurable parallelism

## Dependencies

```
# requirements.txt additions
msal>=1.20.0                 # Microsoft auth
google-auth>=2.0.0           # Google auth
splunk-sdk>=1.7.0            # Splunk connector
elasticsearch>=8.0.0         # Elastic connector
crowdstrike-falconpy>=1.0.0  # CrowdStrike connector
okta>=2.0.0                  # Okta connector
jinja2>=3.0.0                # Report templating
```

## Rollout Plan

### Phase 1: Foundation (Week 1-2)
- [ ] Investigation engine core
- [ ] State management
- [ ] CLI interface

### Phase 2: Connectors (Week 3-5)
- [ ] Microsoft 365 email connector
- [ ] Splunk SIEM connector
- [ ] CrowdStrike EDR connector
- [ ] Azure AD identity connector

### Phase 3: Playbooks (Week 6-7)
- [ ] Phishing investigation playbook
- [ ] Malware investigation playbook
- [ ] Custom playbook support

### Phase 4: Remediation (Week 8-9)
- [ ] Remediation engine
- [ ] Host isolation
- [ ] Account actions
- [ ] Email/URL blocking

### Phase 5: Polish (Week 10)
- [ ] Evidence collection
- [ ] Report generation
- [ ] Documentation

## Success Metrics

| Metric | Target |
|--------|--------|
| Investigation time reduction | >80% |
| Connector reliability | >99% |
| Analyst adoption rate | >70% |
| Investigations per analyst per day | 3x increase |

## Open Questions

1. Which connectors to prioritize first?
2. Approval workflow for remediation - simple or SOAR integration?
3. Evidence storage - local or cloud (S3)?
4. Multi-tenant support needed?
