# SOC Stack Integration Specification

**Version:** 1.0.0
**Status:** Draft
**Priority:** Medium
**Author:** SecOps Helper Team
**Created:** 2026-01-28

## Overview

### Problem Statement

Security tools exist in silos:
- Analysts switch between 8-12 different consoles daily
- Copy-paste IOCs between systems
- Manually create tickets with investigation findings
- Re-enter the same data in multiple places
- No single source of truth for investigations

**Current Workflow Pain Points:**
1. Find IOC in alert → copy to clipboard
2. Paste into VirusTotal, wait for results
3. Paste into SIEM, build query manually
4. Copy findings to Jira ticket
5. Paste IOCs into firewall block list
6. Update SOAR playbook status
7. Send summary to Slack channel

**Result:** 30%+ of analyst time spent on data transfer, not analysis

### Solution

Native integrations that:
1. **Query** enterprise systems directly from CLI
2. **Push** findings to ticketing/SOAR automatically
3. **Generate** SIEM queries in native syntax
4. **Share** results via team communication tools
5. **Sync** IOCs with blocking infrastructure

### Value Proposition

| Activity | Manual Time | Integrated Time | Savings |
|----------|-------------|-----------------|---------|
| SIEM query creation | 3-5 min | 5 sec | 95% |
| Ticket creation | 5-10 min | 30 sec | 95% |
| IOC blocking | 5-15 min | 10 sec | 97% |
| Team notification | 2-3 min | Automatic | 100% |

## User Stories

### US-1: Native SIEM Queries
> As a SOC analyst, I want to search my SIEM directly from the CLI, so I don't have to switch between tools and manually build queries.

### US-2: Auto-Create Tickets
> As a SOC analyst, I want investigation findings automatically formatted as tickets, so I don't spend time on documentation.

### US-3: One-Click Blocking
> As a SOC analyst, I want to block IOCs across all security tools with a single command, so containment takes seconds not minutes.

### US-4: Team Notifications
> As a SOC analyst, I want to share findings with my team instantly via Slack/Teams, so everyone stays informed.

### US-5: SOAR Integration
> As a SOC manager, I want SecOps Helper to work with our SOAR platform, so we can incorporate it into automated playbooks.

## Functional Requirements

### FR-1: SIEM Integration

Direct SIEM querying and query generation:

```bash
# Direct SIEM search
secops siem search "source_ip=185.234.72.14" --last 24h

# Auto-generate queries from IOCs
secops siem query --ioc evil.com
# Output for Splunk:
#   index=* (dest="evil.com" OR query="evil.com" OR url="*evil.com*")
#   | stats count by src_ip, dest, action

# Search with investigation context
secops siem hunt --investigation INV-2026-01-28-0042

# Export SIEM query for manual use
secops siem query --ioc 185.234.72.14 --format splunk
secops siem query --ioc 185.234.72.14 --format elastic
secops siem query --ioc 185.234.72.14 --format sentinel
```

**Supported SIEMs:**

| SIEM | Query | Search | Alert Ingest |
|------|-------|--------|--------------|
| Splunk | ✓ | ✓ | ✓ |
| Elastic SIEM | ✓ | ✓ | ✓ |
| Microsoft Sentinel | ✓ | ✓ | ✓ |
| Chronicle | ✓ | ✓ | ✓ |
| QRadar | ✓ | ✓ | Planned |
| LogRhythm | Planned | Planned | Planned |

**Query Templates:**

```yaml
# .secops/siem_queries.yaml

templates:
  ip_hunt:
    description: "Hunt for IP across all log sources"
    splunk: |
      index=* (src_ip="{ioc}" OR dest_ip="{ioc}" OR c_ip="{ioc}")
      | stats count by index, sourcetype, src_ip, dest_ip
      | sort -count
    elastic: |
      (source.ip:"{ioc}" OR destination.ip:"{ioc}" OR client.ip:"{ioc}")
    sentinel: |
      union *
      | where SrcIP == "{ioc}" or DstIP == "{ioc}"
      | summarize count() by Type, SrcIP, DstIP

  domain_hunt:
    description: "Hunt for domain in DNS and proxy logs"
    splunk: |
      index=dns OR index=proxy
      (query="{ioc}" OR query="*.{ioc}" OR dest="{ioc}" OR url="*{ioc}*")
      | stats count by src_ip, query, dest
    elastic: |
      (dns.question.name:"{ioc}" OR dns.question.name:*.{ioc} OR
       url.domain:"{ioc}" OR destination.domain:"{ioc}")

  process_hunt:
    description: "Hunt for process/hash execution"
    splunk: |
      index=endpoint (process_hash="{ioc}" OR SHA256="{ioc}" OR MD5="{ioc}")
      | stats count by host, user, process_name, process_path
    elastic: |
      (process.hash.sha256:"{ioc}" OR process.hash.md5:"{ioc}")
```

### FR-2: Ticketing Integration

Auto-create and update tickets:

```bash
# Create ticket from investigation
secops ticket create --investigation INV-2026-01-28-0042

# Create ticket manually
secops ticket create \
  --title "Cobalt Strike infection on FINANCE-WS-042" \
  --priority critical \
  --assignee @security-team \
  --description-file findings.md

# Update existing ticket
secops ticket update INCIDENT-1234 --add-comment "Containment complete"
secops ticket update INCIDENT-1234 --attach evidence.zip
secops ticket update INCIDENT-1234 --status resolved

# Link investigation to existing ticket
secops ticket link --investigation INV-2026-01-28-0042 --ticket INCIDENT-1234
```

**Supported Ticketing Systems:**

| System | Create | Update | Attach | Query |
|--------|--------|--------|--------|-------|
| Jira | ✓ | ✓ | ✓ | ✓ |
| ServiceNow | ✓ | ✓ | ✓ | ✓ |
| PagerDuty | ✓ | ✓ | - | ✓ |
| Zendesk | ✓ | ✓ | ✓ | Planned |
| GitHub Issues | ✓ | ✓ | ✓ | ✓ |

**Ticket Templates:**

```yaml
# .secops/ticket_templates.yaml

templates:
  security_incident:
    title: "[{severity}] {alert_title}"
    project: SEC
    type: Incident
    priority_map:
      critical: Highest
      high: High
      medium: Medium
      low: Low
    fields:
      - name: Affected Assets
        value: "{affected_hosts}"
      - name: IOCs
        value: "{iocs_formatted}"
      - name: MITRE ATT&CK
        value: "{mitre_techniques}"
    body: |
      ## Summary
      {executive_summary}

      ## Affected Assets
      {affected_assets_table}

      ## Indicators of Compromise
      | Type | Value | Context |
      |------|-------|---------|
      {iocs_table}

      ## Timeline
      {timeline}

      ## Recommended Actions
      {recommendations}

      ---
      *Generated by SecOps Helper*
      Investigation ID: {investigation_id}

  phishing_report:
    title: "Phishing: {subject}"
    project: SEC
    type: Phishing
    body: |
      ## Email Details
      - **From:** {sender}
      - **Subject:** {subject}
      - **Recipients:** {recipient_count}
      - **Received:** {received_time}

      ## Analysis
      {analysis_summary}

      ## Impact
      - Users who received: {recipient_count}
      - Users who clicked: {clicked_count}
      - Users who submitted credentials: {submitted_count}

      ## Remediation Status
      - [ ] Delete from mailboxes
      - [ ] Block sender domain
      - [ ] Reset affected passwords
      - [ ] User awareness notification
```

### FR-3: Communication Integration

Share findings via team channels:

```bash
# Post to Slack
secops notify slack --channel #soc-alerts \
  --message "Critical: Cobalt Strike detected on FINANCE-WS-042"

# Post investigation summary
secops notify slack --channel #security-team \
  --investigation INV-2026-01-28-0042

# Post with file attachment
secops notify slack --channel #incident-response \
  --file report.pdf \
  --message "Full investigation report attached"

# Auto-notify on critical findings
secops analyze suspicious.exe --ai --notify slack:#soc-alerts
```

**Supported Platforms:**

| Platform | Message | File | Thread | Mention |
|----------|---------|------|--------|---------|
| Slack | ✓ | ✓ | ✓ | ✓ |
| Microsoft Teams | ✓ | ✓ | ✓ | ✓ |
| Discord | ✓ | ✓ | - | ✓ |
| Email | ✓ | ✓ | - | - |
| Webhook | ✓ | - | - | - |

**Message Formatting:**

```bash
secops notify slack --channel #soc-alerts --investigation INV-2026-01-28-0042

# Renders as:
# ┌──────────────────────────────────────────────────────┐
# │ 🔴 CRITICAL SECURITY ALERT                           │
# ├──────────────────────────────────────────────────────┤
# │ Cobalt Strike Infection Detected                      │
# │                                                       │
# │ Host: FINANCE-WS-042                                 │
# │ User: jsmith (Finance Analyst)                       │
# │ C2 Server: 185.234.72.14                             │
# │                                                       │
# │ Status: Investigation in progress                    │
# │ Assigned: @security-team                             │
# │                                                       │
# │ [View Details] [Start Investigation] [Isolate Host] │
# └──────────────────────────────────────────────────────┘
```

### FR-4: SOAR Integration

Work with Security Orchestration platforms:

```bash
# Trigger SOAR playbook
secops soar trigger --playbook phishing-response \
  --input investigation=INV-2026-01-28-0042

# Check playbook status
secops soar status --playbook-run PR-12345

# Export investigation for SOAR import
secops investigate results INV-2026-01-28-0042 --format soar-xsoar
secops investigate results INV-2026-01-28-0042 --format soar-phantom

# Receive SOAR webhook (for bidirectional integration)
secops soar webhook-server --port 8080
```

**Supported SOAR Platforms:**

| Platform | Trigger | Status | Import | Export |
|----------|---------|--------|--------|--------|
| Cortex XSOAR | ✓ | ✓ | ✓ | ✓ |
| Splunk SOAR (Phantom) | ✓ | ✓ | ✓ | ✓ |
| Swimlane | ✓ | ✓ | Planned | ✓ |
| Tines | ✓ | ✓ | ✓ | ✓ |
| Shuffle | ✓ | ✓ | ✓ | ✓ |

### FR-5: IOC Blocking Integration

Push IOCs to security infrastructure:

```bash
# Block IOC across all configured tools
secops block evil.com

# Block with specific targets
secops block 185.234.72.14 --targets firewall,proxy,edr

# Block from investigation
secops block --investigation INV-2026-01-28-0042 --all-iocs

# Preview what would be blocked
secops block evil.com --dry-run

# Unblock (with audit trail)
secops unblock evil.com --reason "False positive confirmed" --ticket INC-1234

# Check block status
secops block status evil.com
```

**Supported Blocking Targets:**

| Category | Product | Block Types |
|----------|---------|-------------|
| Firewall | Palo Alto | IP, Domain, URL |
| Firewall | Fortinet | IP, Domain, URL |
| Firewall | Cisco FTD | IP, Domain |
| Proxy | Zscaler | Domain, URL |
| Proxy | Netskope | Domain, URL |
| EDR | CrowdStrike | Hash, Domain, IP |
| EDR | Microsoft Defender | Hash, Domain, IP |
| Email | Proofpoint | Domain, Email |
| Email | Mimecast | Domain, Email |
| DNS | Cisco Umbrella | Domain |
| WAF | Cloudflare | IP, Domain |

**Block Management:**

```bash
# List active blocks
secops block list --last 7d

# Output:
╔══════════════════════════════════════════════════════════════════════════════╗
║                          ACTIVE IOC BLOCKS                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ IOC              │ Type   │ Targets              │ Blocked     │ By         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ evil.com         │ Domain │ Firewall,Proxy,EDR   │ 2h ago      │ jsmith     ║
║ 185.234.72.14    │ IP     │ Firewall,EDR         │ 2h ago      │ jsmith     ║
║ malware.exe      │ Hash   │ EDR                  │ 1d ago      │ mjohnson   ║
║ phish-domain.com │ Domain │ Email,Proxy          │ 3d ago      │ auto       ║
╚══════════════════════════════════════════════════════════════════════════════╝

# Block audit trail
secops block history evil.com

Block History for evil.com:
  2026-01-28 09:30:00 - BLOCKED by jsmith
    Targets: Firewall (Palo Alto), Proxy (Zscaler), EDR (CrowdStrike)
    Reason: Cobalt Strike C2 server
    Investigation: INV-2026-01-28-0042

  2026-01-28 11:45:00 - VERIFIED by mjohnson
    Confirmed block propagation to all targets

  2026-01-29 14:00:00 - UNBLOCKED by admin
    Reason: Domain sinkholed by law enforcement
    Ticket: INC-5678
```

### FR-6: Threat Intel Platform Integration

Sync with TIP platforms:

```bash
# Push IOCs to threat intel platform
secops tip push --platform misp \
  --event "Cobalt Strike Campaign Jan 2026" \
  --iocs-file iocs.json

# Pull latest threat intel
secops tip pull --platform misp --tags "apt,ransomware" --last 24h

# Check IOC against TIP
secops tip lookup 185.234.72.14

# Sync investigation IOCs to TIP
secops tip sync --investigation INV-2026-01-28-0042
```

**Supported TIPs:**

| Platform | Push | Pull | Lookup | Sync |
|----------|------|------|--------|------|
| MISP | ✓ | ✓ | ✓ | ✓ |
| OpenCTI | ✓ | ✓ | ✓ | ✓ |
| ThreatConnect | ✓ | ✓ | ✓ | ✓ |
| Anomali | ✓ | ✓ | ✓ | Planned |

### FR-7: Configuration Management

Centralized integration configuration:

```yaml
# .secops/integrations.yaml

siem:
  default: splunk_prod

  splunk_prod:
    type: splunk
    host: splunk.company.com
    port: 8089
    token: ${SPLUNK_TOKEN}
    default_index: main

  elastic_prod:
    type: elastic
    hosts:
      - https://elastic1.company.com:9200
      - https://elastic2.company.com:9200
    api_key: ${ELASTIC_API_KEY}

ticketing:
  default: jira

  jira:
    type: jira
    host: https://company.atlassian.net
    email: secops@company.com
    token: ${JIRA_TOKEN}
    default_project: SEC

  servicenow:
    type: servicenow
    host: https://company.service-now.com
    username: secops_integration
    password: ${SNOW_PASSWORD}

communication:
  slack:
    token: ${SLACK_BOT_TOKEN}
    default_channel: "#soc-alerts"

  teams:
    webhook_url: ${TEAMS_WEBHOOK_URL}

blocking:
  firewall:
    type: palo_alto
    host: panorama.company.com
    api_key: ${PALO_API_KEY}
    device_group: Shared

  proxy:
    type: zscaler
    cloud: zscaler.net
    api_key: ${ZSCALER_API_KEY}

  edr:
    type: crowdstrike
    client_id: ${CS_CLIENT_ID}
    client_secret: ${CS_CLIENT_SECRET}

soar:
  type: cortex_xsoar
  host: https://xsoar.company.com
  api_key: ${XSOAR_API_KEY}
```

### FR-8: Integration Health Monitoring

```bash
secops integrations status

╔══════════════════════════════════════════════════════════════════════════════╗
║                      INTEGRATION STATUS                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Integration          │ Status    │ Last Check  │ Latency │ Notes            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ SIEM: Splunk         │ ✅ OK     │ 30s ago     │ 145ms   │                  ║
║ SIEM: Elastic        │ ✅ OK     │ 30s ago     │ 89ms    │                  ║
║ Ticket: Jira         │ ✅ OK     │ 1m ago      │ 234ms   │                  ║
║ Ticket: ServiceNow   │ ⚠️ SLOW   │ 1m ago      │ 2.3s    │ High latency     ║
║ Slack                │ ✅ OK     │ 30s ago     │ 67ms    │                  ║
║ Block: Palo Alto     │ ✅ OK     │ 5m ago      │ 312ms   │                  ║
║ Block: Zscaler       │ ❌ ERROR  │ 5m ago      │ -       │ Auth failed      ║
║ Block: CrowdStrike   │ ✅ OK     │ 5m ago      │ 189ms   │                  ║
║ SOAR: XSOAR          │ ✅ OK     │ 10m ago     │ 456ms   │                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

# Test specific integration
secops integrations test splunk_prod
secops integrations test --all
```

## Technical Design

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Integration Layer                              │
├─────────────────────────────────────────────────────────────────┤
│  CLI Commands                                                   │
│  secops siem | ticket | notify | block | soar | tip            │
├─────────────────────────────────────────────────────────────────┤
│  Integration Manager                                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Config      │  │ Connection  │  │ Health      │            │
│  │ Loader      │  │ Pool        │  │ Monitor     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  Connectors                                                     │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ │
│  │ SIEM  │ │Ticket │ │Comms  │ │Block  │ │ SOAR  │ │  TIP  │ │
│  │Splunk │ │ Jira  │ │ Slack │ │ PAN   │ │ XSOAR │ │ MISP  │ │
│  │Elastic│ │ SNOW  │ │ Teams │ │Zscaler│ │Phantom│ │OpenCTI│ │
│  └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ │
├─────────────────────────────────────────────────────────────────┤
│  Utilities                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Query       │  │ Template    │  │ Retry       │            │
│  │ Builder     │  │ Engine      │  │ Handler     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
src/secops_helper/
├── integrations/
│   ├── __init__.py
│   ├── manager.py              # Integration manager
│   ├── config.py               # Configuration loader
│   ├── health.py               # Health monitoring
│   ├── siem/
│   │   ├── __init__.py
│   │   ├── base.py             # Abstract SIEM connector
│   │   ├── splunk.py
│   │   ├── elastic.py
│   │   ├── sentinel.py
│   │   └── query_builder.py    # Query generation
│   ├── ticketing/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── jira.py
│   │   ├── servicenow.py
│   │   └── templates.py
│   ├── communication/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── slack.py
│   │   ├── teams.py
│   │   └── formatters.py
│   ├── blocking/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── palo_alto.py
│   │   ├── zscaler.py
│   │   ├── crowdstrike.py
│   │   └── audit.py
│   ├── soar/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── xsoar.py
│   │   └── phantom.py
│   └── tip/
│       ├── __init__.py
│       ├── base.py
│       ├── misp.py
│       └── opencti.py
```

## CLI Interface

```bash
# SIEM
secops siem search "<query>" [--source splunk|elastic] [--last 24h]
secops siem query --ioc <ioc> [--format splunk|elastic|sentinel]
secops siem hunt --investigation <id>

# Ticketing
secops ticket create --investigation <id>
secops ticket create --title "..." --priority high --assignee @team
secops ticket update <ticket-id> --add-comment "..." [--attach file]
secops ticket link --investigation <id> --ticket <ticket-id>

# Communication
secops notify slack --channel #channel --message "..."
secops notify slack --channel #channel --investigation <id>
secops notify teams --channel "..." --message "..."
secops notify email --to team@company.com --subject "..." --body-file report.md

# Blocking
secops block <ioc> [--targets firewall,proxy,edr]
secops block --investigation <id> --all-iocs
secops unblock <ioc> --reason "..." --ticket <ticket-id>
secops block list [--last 7d]
secops block status <ioc>
secops block history <ioc>

# SOAR
secops soar trigger --playbook <name> --input key=value
secops soar status --playbook-run <id>
secops soar list-playbooks

# Threat Intel
secops tip push --platform misp --event "..." --iocs-file iocs.json
secops tip pull --platform misp --tags "apt" --last 24h
secops tip lookup <ioc>

# Management
secops integrations status
secops integrations test <name>
secops integrations config
```

## Non-Functional Requirements

### NFR-1: Reliability
- Automatic retry with exponential backoff
- Graceful degradation if integration unavailable
- Transaction logging for audit

### NFR-2: Security
- Credentials encrypted at rest
- API keys in environment variables or secrets manager
- Audit trail for all blocking actions

### NFR-3: Performance
- Connection pooling for frequent integrations
- Async operations where possible
- Caching for repeated queries

## Rollout Plan

### Phase 1: Core (Week 1-2)
- [ ] Integration manager framework
- [ ] Configuration management
- [ ] Health monitoring

### Phase 2: SIEM (Week 3-4)
- [ ] Splunk connector
- [ ] Elastic connector
- [ ] Query builder

### Phase 3: Ticketing & Comms (Week 5-6)
- [ ] Jira connector
- [ ] Slack connector
- [ ] Template engine

### Phase 4: Blocking & SOAR (Week 7-8)
- [ ] Blocking framework
- [ ] Palo Alto connector
- [ ] XSOAR connector

## Success Metrics

| Metric | Target |
|--------|--------|
| Integration reliability | >99% |
| Time to block IOC | <30 sec |
| Ticket creation time | <10 sec |
| Query generation accuracy | 100% |
