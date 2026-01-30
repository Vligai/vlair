# Alert Triage & Prioritization Specification

**Version:** 1.0.0
**Status:** Draft
**Priority:** High
**Author:** vlair Team
**Created:** 2026-01-28

## Overview

### Problem Statement

SOC analysts face alert fatigue:
- **500-1000+ alerts per day** in typical enterprise
- **85-95% are false positives** or low priority
- **Critical alerts get buried** in the noise
- **Analyst burnout** from repetitive triage

Current workflow:
1. Alert fires → analyst opens console
2. Manually reviews alert details (2-5 min)
3. Checks related logs (3-5 min)
4. Decides: investigate, escalate, or close (1-2 min)
5. Documents decision (1-2 min)

**Result:** 8-15 minutes per alert × 100 alerts = entire shift spent on triage

### Solution

Intelligent alert triage that:
1. **Ingests** alerts from SIEM/EDR/XDR
2. **Enriches** with context (asset info, user info, threat intel)
3. **Classifies** priority using ML/rules
4. **Deduplicates** and groups related alerts
5. **Recommends** actions (investigate, close, auto-remediate)
6. **Learns** from analyst decisions

### Value Proposition

| Metric | Before | After |
|--------|--------|-------|
| Alerts requiring manual review | 100% | 30% |
| Time to identify critical alerts | 2+ hours | <5 minutes |
| False positive closure time | 10 min | 30 sec (auto) |
| Analyst alert throughput | 50/day | 200/day |
| Missed critical alerts | Common | Rare |

## User Stories

### US-1: Priority Queue
> As a SOC analyst, I want alerts automatically sorted by actual risk, so I work on the most critical issues first.

### US-2: Auto-Close False Positives
> As a SOC analyst, I want obvious false positives auto-closed with documentation, so I don't waste time on known-good activity.

### US-3: Alert Grouping
> As a SOC analyst, I want related alerts grouped together, so I can investigate an incident holistically instead of 50 individual alerts.

### US-4: Context at a Glance
> As a SOC analyst, I want relevant context pre-loaded (asset criticality, user role, recent activity), so I can make decisions faster.

### US-5: Learn from Decisions
> As a SOC manager, I want the system to learn from analyst decisions, so triage accuracy improves over time.

## Functional Requirements

### FR-1: Alert Ingestion

Pull alerts from multiple sources:

```bash
# Configure alert sources
vlair triage sources add splunk --name prod-splunk \
  --host splunk.company.com \
  --token $SPLUNK_TOKEN \
  --index alerts

vlair triage sources add crowdstrike --name prod-cs \
  --client-id $CS_CLIENT \
  --client-secret $CS_SECRET

# Manual alert import
vlair triage import alerts.json
vlair triage import --stdin < alerts.csv
```

**Supported Sources:**
| Source | Method | Alert Types |
|--------|--------|-------------|
| Splunk | Saved search / API | All |
| Elastic SIEM | API / Webhook | All |
| CrowdStrike | API | EDR alerts |
| Microsoft Defender | API | EDR/Email alerts |
| Palo Alto Cortex | API | XDR alerts |
| Custom | Webhook / File | Any JSON/CSV |

### FR-2: Triage Queue Interface

```bash
# View prioritized queue
vlair triage queue

# Output:
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ALERT TRIAGE QUEUE                                  ║
║                    47 alerts pending │ 12 high priority                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ PRI │ ID       │ TITLE                        │ SOURCE │ AGE  │ RECOMMENDED  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ ██▓ │ ALT-1042 │ Cobalt Strike beacon pattern │ CS     │ 2m   │ INVESTIGATE  ║
║ ██▓ │ ALT-1039 │ Data exfil to external IP    │ Splunk │ 8m   │ INVESTIGATE  ║
║ ██░ │ ALT-1041 │ Suspicious PowerShell exec   │ CS     │ 5m   │ INVESTIGATE  ║
║ ██░ │ ALT-1038 │ Multiple failed logins       │ Splunk │ 12m  │ REVIEW       ║
║ █░░ │ ALT-1040 │ Scheduled task created       │ CS     │ 6m   │ REVIEW       ║
║ ░░░ │ ALT-1037 │ Chrome update traffic        │ Splunk │ 15m  │ AUTO-CLOSE   ║
║ ░░░ │ ALT-1036 │ Known scanner activity       │ Splunk │ 18m  │ AUTO-CLOSE   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ [i] Investigate  [r] Review  [c] Close  [g] Group  [n] Next  [q] Quit        ║
╚══════════════════════════════════════════════════════════════════════════════╝

# Focus on specific priority
vlair triage queue --priority critical
vlair triage queue --priority high
vlair triage queue --recommendation investigate

# Interactive mode
vlair triage interactive
```

### FR-3: Alert Detail View

```bash
vlair triage show ALT-1042

╔══════════════════════════════════════════════════════════════════════════════╗
║ ALERT: ALT-1042                                          PRIORITY: CRITICAL  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Title: Cobalt Strike beacon pattern detected                                 ║
║ Source: CrowdStrike │ Time: 2026-01-28 09:15:23 UTC │ Age: 2 minutes        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ CONTEXT                                                                      ║
║ ─────────────────────────────────────────────────────────────────────────── ║
║ Host: FINANCE-WS-042                                                         ║
║   Asset Criticality: HIGH (Finance department)                              ║
║   OS: Windows 10 Enterprise                                                  ║
║   Last logged user: jsmith (Finance Analyst)                                ║
║   Recent alerts on host: 0 in past 30 days                                  ║
║                                                                              ║
║ User: jsmith                                                                 ║
║   Department: Finance │ Title: Senior Analyst                               ║
║   Risk score: LOW (no prior incidents)                                      ║
║   Recent activity: Normal patterns                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ DETECTION DETAILS                                                            ║
║ ─────────────────────────────────────────────────────────────────────────── ║
║ Process: rundll32.exe                                                        ║
║ Command: rundll32.exe C:\Users\jsmith\AppData\Local\Temp\update.dll,Start   ║
║ Parent: EXCEL.EXE                                                           ║
║ Network: Beacon pattern to 185.234.72.14:443 (every 60s)                    ║
║                                                                              ║
║ IOC Reputation:                                                              ║
║   185.234.72.14 - MALICIOUS (Cobalt Strike C2, TA505)                       ║
║   update.dll - 42/68 VT detections (Cobalt Strike stager)                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ TRIAGE RECOMMENDATION                                                        ║
║ ─────────────────────────────────────────────────────────────────────────── ║
║ Action: INVESTIGATE IMMEDIATELY                                              ║
║ Confidence: 96%                                                              ║
║                                                                              ║
║ Reasoning:                                                                   ║
║   • Known Cobalt Strike C2 infrastructure (high confidence)                  ║
║   • Beacon pattern matches CS default profile                                ║
║   • Excel → rundll32 execution chain typical of macro delivery              ║
║   • Host is in Finance (high-value target)                                  ║
║   • No prior alerts suggests fresh compromise                               ║
║                                                                              ║
║ Similar past incidents: 3 (all confirmed true positive)                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ SUGGESTED ACTIONS                                                            ║
║ ─────────────────────────────────────────────────────────────────────────── ║
║ 1. [Enter] Start investigation (vlair investigate malware --alert ALT-1042) ║
║ 2. [i] Isolate host immediately                                             ║
║ 3. [e] Escalate to IR team                                                  ║
║ 4. [c] Close as false positive (explain why)                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### FR-4: Priority Scoring Engine

Multi-factor priority scoring:

```python
class PriorityScore:
    """
    Priority score 0-100, composed of multiple factors
    """

    def calculate(self, alert: Alert, context: Context) -> int:
        score = 0

        # Detection confidence (0-25 points)
        score += self.detection_confidence_score(alert)

        # Asset criticality (0-20 points)
        score += self.asset_criticality_score(context.asset)

        # Threat intel match (0-20 points)
        score += self.threat_intel_score(alert.iocs)

        # User risk (0-15 points)
        score += self.user_risk_score(context.user)

        # Historical pattern (0-10 points)
        score += self.historical_score(alert, context)

        # Temporal factors (0-10 points)
        score += self.temporal_score(alert)

        return min(100, score)

    def detection_confidence_score(self, alert: Alert) -> int:
        """Score based on detection rule quality"""
        # High-fidelity detections (Cobalt Strike, known malware)
        if alert.rule_category in ['apt', 'ransomware', 'c2']:
            return 25
        # Medium-fidelity (suspicious behavior)
        if alert.rule_category in ['suspicious', 'anomaly']:
            return 15
        # Low-fidelity (generic)
        return 5

    def asset_criticality_score(self, asset: Asset) -> int:
        """Score based on asset importance"""
        criticality_scores = {
            'critical': 20,    # Domain controllers, DB servers
            'high': 15,        # Finance, HR systems
            'medium': 10,      # Standard workstations
            'low': 5           # Test systems, printers
        }
        return criticality_scores.get(asset.criticality, 10)
```

**Priority Levels:**

| Score | Level | Response Time | Action |
|-------|-------|---------------|--------|
| 80-100 | CRITICAL | <15 min | Investigate immediately, consider auto-isolate |
| 60-79 | HIGH | <1 hour | Investigate today |
| 40-59 | MEDIUM | <4 hours | Review when possible |
| 20-39 | LOW | <24 hours | Batch review |
| 0-19 | MINIMAL | Auto-close | Auto-close with documentation |

### FR-5: Auto-Close Rules

Define rules for automatic closure of known false positives:

```yaml
# .secops/autoclose_rules.yaml

rules:
  - name: Chrome Updates
    description: Chrome browser auto-update traffic
    conditions:
      - field: process_name
        operator: equals
        value: GoogleUpdate.exe
      - field: destination_domain
        operator: matches
        value: "*.google.com"
    action: close
    reason: "Known-good Chrome update process"

  - name: IT Security Scanners
    description: Authorized vulnerability scanners
    conditions:
      - field: source_ip
        operator: in
        value: ["10.1.100.10", "10.1.100.11"]
      - field: alert_type
        operator: in
        value: ["port_scan", "vulnerability_scan"]
    action: close
    reason: "Authorized security scanner from IT Security team"

  - name: Backup Traffic
    description: Known backup server traffic
    conditions:
      - field: destination_ip
        operator: in
        value: ["10.2.50.0/24"]
      - field: alert_type
        operator: equals
        value: "large_data_transfer"
      - field: time_of_day
        operator: between
        value: ["02:00", "06:00"]
    action: close
    reason: "Scheduled backup window to backup servers"

  - name: Service Account Activity
    description: Known service account patterns
    conditions:
      - field: username
        operator: matches
        value: "^svc_.*"
      - field: source_host
        operator: in_cmdb_group
        value: "application_servers"
    action: lower_priority
    adjustment: -30
    reason: "Expected service account activity"
```

```bash
# Manage auto-close rules
vlair triage rules list
vlair triage rules add --file new_rule.yaml
vlair triage rules test --alert ALT-1042  # Test if rules would match
vlair triage rules stats  # Show rule effectiveness
```

### FR-6: Alert Grouping

Group related alerts into incidents:

```bash
vlair triage groups

╔══════════════════════════════════════════════════════════════════════════════╗
║                          ALERT GROUPS                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ GROUP-001: Potential Cobalt Strike Infection (CRITICAL)                      ║
║   Alerts: 5 │ Hosts: 1 │ First: 09:15 │ Last: 09:23                         ║
║   ├── ALT-1042: Cobalt Strike beacon pattern                                 ║
║   ├── ALT-1043: Suspicious scheduled task                                    ║
║   ├── ALT-1044: LSASS memory access                                          ║
║   ├── ALT-1045: Lateral movement attempt (FINANCE-WS-042 → DC01)            ║
║   └── ALT-1046: Admin share access                                          ║
║                                                                              ║
║ GROUP-002: Brute Force Campaign (HIGH)                                       ║
║   Alerts: 23 │ Users: 8 │ Source IPs: 2 │ First: 08:45 │ Last: 09:20        ║
║   └── 23 failed login alerts from 185.x.x.x and 91.x.x.x                    ║
║                                                                              ║
║ GROUP-003: Vulnerability Scanner Activity (AUTO-CLOSED)                      ║
║   Alerts: 47 │ First: 02:00 │ Last: 04:30                                   ║
║   └── Authorized Qualys scan from 10.1.100.10                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Grouping Criteria:**
- Same host within time window
- Same user within time window
- Same attack technique (MITRE ATT&CK)
- Related IOCs (same C2, same malware family)
- Same source IP (for external attacks)

### FR-7: Analyst Feedback Loop

Learn from analyst decisions:

```bash
# Close alert with feedback
vlair triage close ALT-1037 --reason "false_positive" \
  --comment "Chrome update traffic, known good"

# Confirm true positive
vlair triage confirm ALT-1042 --severity critical \
  --comment "Confirmed Cobalt Strike, escalated to IR"

# Override recommendation
vlair triage override ALT-1040 --new-priority low \
  --reason "Expected admin activity during maintenance"
```

**Feedback Used For:**
1. Training ML models on analyst decisions
2. Refining auto-close rules
3. Adjusting detection rule fidelity scores
4. Identifying rule tuning opportunities

```bash
# View feedback statistics
vlair triage feedback-stats

Feedback Statistics (Last 30 days):
  Total alerts processed: 3,247

  Recommendation Accuracy:
    INVESTIGATE recommended: 312 (accuracy: 89%)
    AUTO-CLOSE recommended: 2,145 (accuracy: 97%)
    REVIEW recommended: 790 (accuracy: 76%)

  Top False Positive Sources:
    1. "Suspicious PowerShell" - 45 FPs (tuning recommended)
    2. "Large file download" - 32 FPs (add exception for Dropbox)
    3. "After-hours login" - 28 FPs (timezone issue)

  Suggested Rule Improvements:
    • Add Dropbox to allowed file transfer destinations
    • Adjust working hours for APAC users
    • Whitelist IT admin group for PowerShell usage
```

### FR-8: Context Enrichment

Automatic enrichment from enterprise sources:

```yaml
# .secops/enrichment.yaml

sources:
  # Asset information
  cmdb:
    provider: servicenow
    endpoint: https://company.service-now.com
    credentials: ${SNOW_CREDENTIALS}
    mappings:
      hostname → asset_criticality, owner, department, os

  # User information
  identity:
    provider: azure_ad
    tenant_id: ${AAD_TENANT}
    mappings:
      username → department, title, manager, risk_score

  # Threat intelligence
  threat_intel:
    providers:
      - virustotal
      - abuseipdb
      - internal_ioc_db
    mappings:
      ip, domain, hash → reputation, threat_actor, malware_family

  # Historical context
  history:
    provider: internal
    lookback: 90d
    mappings:
      host, user → prior_alerts, prior_incidents, false_positive_rate
```

### FR-9: Metrics and Reporting

```bash
vlair triage metrics

╔══════════════════════════════════════════════════════════════════════════════╗
║                    TRIAGE METRICS - Last 24 Hours                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Alert Volume                          │ Triage Performance                   ║
║ ──────────────────────────────────────│────────────────────────────────────  ║
║ Total alerts:           487           │ Mean time to triage:      3.2 min    ║
║ Auto-closed:            312 (64%)     │ Mean time to investigate: 12.4 min   ║
║ Analyst reviewed:       175 (36%)     │ Alerts per analyst/hour:  8.3        ║
║ True positives:         23  (5%)      │                                      ║
║                                       │                                      ║
║ By Priority                           │ By Recommendation                    ║
║ ──────────────────────────────────────│────────────────────────────────────  ║
║ Critical:    8                        │ Investigate:   47                    ║
║ High:       39                        │ Review:       128                    ║
║ Medium:    128                        │ Auto-close:   312                    ║
║ Low:       312                        │                                      ║
║                                       │                                      ║
║ Top Alert Types                       │ Top Affected Assets                  ║
║ ──────────────────────────────────────│────────────────────────────────────  ║
║ 1. Suspicious login (124)             │ 1. FINANCE-WS-042 (12 alerts)        ║
║ 2. Malware detected (89)              │ 2. DC01 (8 alerts)                   ║
║ 3. Policy violation (76)              │ 3. WEB-PROD-01 (7 alerts)            ║
╚══════════════════════════════════════════════════════════════════════════════╝

# Export metrics
vlair triage metrics --format csv --output triage_metrics.csv
vlair triage metrics --format json | jq .
```

### FR-10: Real-Time Mode

Continuous triage with notifications:

```bash
# Start real-time triage daemon
vlair triage watch --notify slack --channel #soc-alerts

# Output:
[09:15:23] 🔴 CRITICAL: Cobalt Strike beacon (FINANCE-WS-042)
           → Recommended: INVESTIGATE IMMEDIATELY
           → Notified: #soc-alerts

[09:16:45] 🟡 MEDIUM: Suspicious PowerShell (IT-WS-103)
           → Recommended: REVIEW

[09:17:02] ⚪ AUTO-CLOSED: Chrome update (87 alerts)
           → Rule: "Chrome Updates"

[09:18:33] 🔴 CRITICAL: Lateral movement detected (DC01)
           → Recommended: INVESTIGATE IMMEDIATELY
           → Notified: #soc-alerts, @incident-commander
           → Auto-action: Host isolation initiated
```

## Technical Design

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Triage Engine                               │
├─────────────────────────────────────────────────────────────────┤
│  Alert Sources                                                  │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │
│  │ Splunk │ │ Elastic│ │ CS     │ │ MDE    │ │Webhook │       │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘       │
├─────────────────────────────────────────────────────────────────┤
│  Processing Pipeline                                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Ingest   │→│ Enrich   │→│ Score    │→│ Group    │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│        ↓            ↓            ↓            ↓                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Normalize│ │ Context  │ │ Priority │ │ Correlate│          │
│  │ Schema   │ │ Lookup   │ │ Engine   │ │ Alerts   │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
├─────────────────────────────────────────────────────────────────┤
│  Decision Layer                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │ Auto-Close      │ │ ML Classifier   │ │ Recommendation  │  │
│  │ Rules Engine    │ │ (optional)      │ │ Engine          │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Output Layer                                                   │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │
│  │ Queue  │ │ Notify │ │ Metrics│ │ SOAR   │ │ Ticket │       │
│  │ UI     │ │ Slack  │ │ Export │ │ Export │ │ Create │       │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
src/secops_helper/
├── triage/
│   ├── __init__.py
│   ├── engine.py              # Main triage orchestrator
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── base.py            # Abstract alert source
│   │   ├── splunk.py
│   │   ├── elastic.py
│   │   ├── crowdstrike.py
│   │   └── webhook.py
│   ├── enrich/
│   │   ├── __init__.py
│   │   ├── cmdb.py            # Asset enrichment
│   │   ├── identity.py        # User enrichment
│   │   ├── threat_intel.py    # IOC enrichment
│   │   └── history.py         # Historical context
│   ├── score/
│   │   ├── __init__.py
│   │   ├── priority.py        # Priority scoring
│   │   ├── factors.py         # Individual factors
│   │   └── ml_classifier.py   # Optional ML model
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py          # Rules engine
│   │   ├── autoclose.py       # Auto-close rules
│   │   └── parser.py          # YAML rule parser
│   ├── group/
│   │   ├── __init__.py
│   │   └── correlator.py      # Alert grouping
│   ├── output/
│   │   ├── __init__.py
│   │   ├── queue.py           # Queue management
│   │   ├── notify.py          # Notifications
│   │   └── metrics.py         # Metrics collection
│   └── feedback.py            # Analyst feedback
```

## CLI Interface

```bash
# Queue management
vlair triage queue [--priority critical|high|medium|low]
vlair triage show <alert-id>
vlair triage interactive

# Alert actions
vlair triage close <alert-id> --reason <reason> [--comment "..."]
vlair triage confirm <alert-id> --severity <level> [--comment "..."]
vlair triage escalate <alert-id> --to <team> [--comment "..."]
vlair triage investigate <alert-id>  # Launch investigation

# Grouping
vlair triage groups
vlair triage group show <group-id>
vlair triage group merge <group-id-1> <group-id-2>

# Rules
vlair triage rules list
vlair triage rules add --file <rule.yaml>
vlair triage rules test --alert <alert-id>
vlair triage rules stats

# Sources
vlair triage sources list
vlair triage sources add <type> --name <name> [options]
vlair triage sources test <name>

# Real-time
vlair triage watch [--notify slack|email|teams]

# Metrics
vlair triage metrics [--period 24h|7d|30d] [--format console|json|csv]
vlair triage feedback-stats
```

## Non-Functional Requirements

### NFR-1: Performance
- Process 100 alerts/minute sustained
- <1 second per alert enrichment
- Real-time queue updates

### NFR-2: Accuracy
- Auto-close precision >98%
- Priority scoring correlation with analyst decisions >85%
- False negative rate <1% for critical alerts

### NFR-3: Reliability
- 99.9% uptime for real-time mode
- No alert loss during outages (queue persistence)
- Graceful degradation if enrichment sources unavailable

## Rollout Plan

### Phase 1: Foundation (Week 1-2)
- [ ] Alert normalization schema
- [ ] Splunk ingest connector
- [ ] Basic priority scoring
- [ ] CLI queue interface

### Phase 2: Enrichment (Week 3-4)
- [ ] CMDB integration
- [ ] Threat intel enrichment
- [ ] User context enrichment
- [ ] Historical context

### Phase 3: Intelligence (Week 5-6)
- [ ] Auto-close rules engine
- [ ] Alert grouping
- [ ] Recommendation engine
- [ ] Feedback collection

### Phase 4: Production (Week 7-8)
- [ ] Real-time watch mode
- [ ] Notifications
- [ ] Metrics dashboard
- [ ] Additional connectors

## Success Metrics

| Metric | Target |
|--------|--------|
| Alert processing rate | 100/min |
| Auto-close precision | >98% |
| Time to critical alert | <5 min |
| Analyst throughput increase | 3x |
