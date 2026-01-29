# AI-Powered Analysis Specification

**Version:** 1.0.0
**Status:** Draft
**Priority:** High
**Author:** SecOps Helper Team
**Created:** 2026-01-28

## Overview

### Problem Statement

Current SecOps Helper aggregates data from multiple threat intelligence sources but leaves interpretation to the analyst. A typical hash lookup returns:

```
Hash: 44d88612fea8a8f36de82e1278abb02f
VirusTotal: 45/70 detections
MalwareBazaar: Emotet
First Seen: 2026-01-15
```

**The analyst still has to:**
1. Understand what "Emotet" means and its typical behavior
2. Determine the severity and urgency
3. Figure out what to investigate next
4. Decide on containment actions
5. Write up findings for the ticket

This takes 15-30 minutes per indicator. With 50+ alerts/day, analysts spend most of their time on repetitive interpretation rather than actual investigation.

### Solution

Add an AI analysis layer that:
1. **Interprets** raw threat intel data into plain-English findings
2. **Correlates** multiple IOCs to identify campaign patterns
3. **Prioritizes** based on threat severity and organizational context
4. **Recommends** specific next steps and containment actions
5. **Generates** investigation summaries and report drafts

### Value Proposition

| Metric | Before | After |
|--------|--------|-------|
| Time per indicator analysis | 15-30 min | 2-3 min |
| Missed correlations | Common | Rare |
| Report writing time | 20 min | 2 min (review only) |
| Junior analyst effectiveness | Limited | Near-senior level |

## User Stories

### US-1: Quick Indicator Assessment
> As a Tier 1 SOC analyst, I want to get an instant assessment of an IOC's risk level and what it means, so I can quickly decide whether to escalate or close the alert.

### US-2: Correlation Discovery
> As an incident responder, I want the tool to automatically identify connections between multiple IOCs, so I can understand the full scope of an attack.

### US-3: Investigation Guidance
> As a junior analyst, I want specific recommendations on what to investigate next, so I can handle incidents without always asking senior staff.

### US-4: Report Generation
> As any analyst, I want auto-generated investigation summaries, so I can document findings without spending 20 minutes writing.

### US-5: Threat Context
> As a threat intel analyst, I want background on threat actors and malware families, so I can understand adversary TTPs.

## Functional Requirements

### FR-1: AI-Enhanced Analysis Command
```bash
secops analyze <input> --ai
secops analyze <input> --ai --depth thorough
```

The `--ai` flag enables AI interpretation of results. Without it, behavior is unchanged (raw data only).

### FR-2: Intelligent Summary Generation
Given raw threat intel data, generate:
- **Verdict**: MALICIOUS / SUSPICIOUS / CLEAN with confidence percentage
- **Threat Type**: Malware family, attack category (phishing, ransomware, C2, etc.)
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW with justification
- **Key Findings**: 3-5 bullet points of the most important observations
- **Threat Context**: Brief background on the threat actor/malware if known

**Example Output:**
```
VERDICT: MALICIOUS (92% confidence)
SEVERITY: HIGH - Active ransomware precursor

Key Findings:
  - Hash matches Emotet loader (TA542) first seen Jan 15, 2026
  - This variant contacts 3 C2 servers, 2 are currently active
  - Emotet typically delivers Cobalt Strike within 24-48 hours
  - File was likely delivered via malicious Excel macro

Threat Context:
  Emotet is a modular banking trojan turned malware-as-a-service
  platform. After initial infection, TA542 typically sells access
  to ransomware operators (Conti, Ryuk). Mean time to ransomware
  deployment is 48-72 hours.
```

### FR-3: Recommended Actions
Generate specific, actionable next steps based on the threat type:

```
Recommended Actions:
  IMMEDIATE (next 1 hour):
    1. Isolate affected host from network
    2. Block C2 domains at firewall: evil1.com, evil2.com
    3. Search SIEM for other hosts contacting these domains

  SHORT-TERM (next 24 hours):
    4. Collect memory dump before reboot
    5. Check for lateral movement (Event ID 4624 Type 3)
    6. Notify affected user and reset credentials

  Query for your SIEM:
    index=firewall dest_ip IN (1.2.3.4, 5.6.7.8) OR
    query IN (*evil1.com*, *evil2.com*)
```

### FR-4: Multi-IOC Correlation
When analyzing multiple IOCs (file, email, list), identify relationships:

```bash
secops analyze phishing.eml --ai

Correlation Analysis:
  - Sender domain (fakepaypal.com) registered 2 days ago
  - Attachment hash seen in 47 other samples this week
  - All samples contact same C2 infrastructure
  - Campaign attribution: Likely TA505 based on TTPs

  Related IOCs from this campaign:
    Domains: fakepaypal.com, secure-update.net, doc-viewer.org
    IPs: 185.234.xx.xx, 91.215.xx.xx
    Hashes: abc123..., def456..., ghi789...
```

### FR-5: Investigation Summary Export
Generate formatted reports for ticketing systems:

```bash
secops analyze suspicious.exe --ai --report markdown > findings.md
secops analyze suspicious.exe --ai --report jira
```

**Markdown Output:**
```markdown
# Investigation Summary

**Date:** 2026-01-28
**Analyst:** Auto-generated
**IOC:** suspicious.exe (SHA256: abc123...)

## Verdict
MALICIOUS - Emotet loader with active C2 infrastructure

## Executive Summary
The analyzed file is a confirmed Emotet malware sample that poses
immediate risk of ransomware deployment. Recommend isolation and
full IR engagement.

## Technical Findings
[Detailed findings here...]

## Recommended Actions
[Action items here...]

## IOCs for Blocking
| Type | Value | Context |
|------|-------|---------|
| Domain | evil.com | C2 server |
| IP | 1.2.3.4 | C2 server |
| Hash | abc123 | Malware sample |
```

### FR-6: Confidence Scoring
All AI-generated assessments include confidence scores:

- **HIGH (>80%)**: Strong signals from multiple sources, known threat
- **MEDIUM (50-80%)**: Some concerning signals, needs verification
- **LOW (<50%)**: Insufficient data, manual review required

When confidence is low, explicitly state what's missing:
```
Confidence: LOW (35%)
Reason: Hash not found in any threat intel source. Only behavioral
analysis available. Recommend sandbox detonation for confirmation.
```

### FR-7: Contextual Awareness
Allow users to provide organizational context for better recommendations:

```bash
# Set organization profile
secops config set org.industry healthcare
secops config set org.size enterprise
secops config set org.critical_assets "patient data, EMR systems"

# Analysis now considers context
secops analyze ransomware.exe --ai

# Output includes:
"CRITICAL SEVERITY for healthcare organizations - ransomware
operators specifically target hospitals due to urgency to restore
patient care systems. Recent Clop attacks on healthcare averaged
$4.5M ransom demands."
```

### FR-8: Offline/Local AI Option
Support local LLM inference for sensitive environments:

```bash
# Use local Ollama instance
secops config set ai.provider ollama
secops config set ai.model llama3:70b
secops config set ai.endpoint http://localhost:11434

# Use local LM Studio
secops config set ai.provider lmstudio
secops config set ai.endpoint http://localhost:1234
```

### FR-9: Privacy Controls
Never send raw file contents or sensitive data to cloud LLMs. Only send:
- Hashes (not file contents)
- Defanged IOCs
- Aggregated threat intel results
- Generic behavioral descriptions

```bash
# Show what would be sent to AI
secops analyze file.exe --ai --dry-run

# Output:
"The following will be sent to AI provider (OpenAI):
 - File hash: abc123...
 - VT results: 45/70 detections, families: [Emotet, Trojan.Generic]
 - Sandbox behavior: Creates scheduled task, contacts 3 domains

 NOT sent: File contents, internal IPs, usernames"
```

### FR-10: Caching and Rate Limiting
- Cache AI responses for identical inputs (24-hour TTL)
- Respect API rate limits (configurable)
- Track token usage and costs

```bash
secops ai-stats

AI Usage Statistics:
  Today: 45 requests, ~12,500 tokens, ~$0.25
  This month: 892 requests, ~245,000 tokens, ~$4.90
  Cache hit rate: 34%
```

## Technical Design

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecOps Helper                             │
├─────────────────────────────────────────────────────────────────┤
│  CLI Layer (secops analyze --ai)                                │
├─────────────────────────────────────────────────────────────────┤
│  Orchestration Layer                                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Detector    │  │ Tool Runner │  │ AI Analyzer │            │
│  │ (type)      │  │ (raw data)  │  │ (interpret) │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  AI Provider Abstraction Layer                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ OpenAI   │ │ Anthropic│ │ Ollama   │ │ Azure    │          │
│  │ (GPT-4)  │ │ (Claude) │ │ (Local)  │ │ OpenAI   │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
├─────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Prompt      │  │ Response    │  │ Context     │            │
│  │ Templates   │  │ Cache       │  │ Store       │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### AI Provider Interface

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class AIResponse:
    content: str
    confidence: float
    tokens_used: int
    model: str
    cached: bool = False

class AIProvider(ABC):
    """Abstract base class for AI providers"""

    @abstractmethod
    def analyze(
        self,
        prompt: str,
        context: Dict[str, Any],
        max_tokens: int = 2000
    ) -> AIResponse:
        """Send analysis request to AI provider"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is configured and reachable"""
        pass

class OpenAIProvider(AIProvider):
    """OpenAI GPT-4 implementation"""

    def __init__(self, api_key: str, model: str = "gpt-4-turbo"):
        self.api_key = api_key
        self.model = model
        self.client = OpenAI(api_key=api_key)

    def analyze(self, prompt: str, context: Dict, max_tokens: int = 2000) -> AIResponse:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SECURITY_ANALYST_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.3  # Lower temperature for more consistent analysis
        )
        return AIResponse(
            content=response.choices[0].message.content,
            confidence=self._extract_confidence(response),
            tokens_used=response.usage.total_tokens,
            model=self.model
        )

class OllamaProvider(AIProvider):
    """Local Ollama implementation for air-gapped environments"""

    def __init__(self, endpoint: str = "http://localhost:11434", model: str = "llama3"):
        self.endpoint = endpoint
        self.model = model

    def analyze(self, prompt: str, context: Dict, max_tokens: int = 2000) -> AIResponse:
        # Implementation for local Ollama inference
        pass
```

### Prompt Engineering

System prompt for security analysis:

```python
SECURITY_ANALYST_SYSTEM_PROMPT = """
You are an expert security analyst assistant. Your role is to interpret
threat intelligence data and provide actionable security assessments.

GUIDELINES:
1. Be specific and actionable - vague warnings are not helpful
2. Prioritize by actual risk, not theoretical possibilities
3. Consider the full attack chain, not just individual indicators
4. Provide confidence levels and explain uncertainty
5. Recommend specific next steps, not generic advice
6. Use industry-standard terminology (MITRE ATT&CK, etc.)
7. Never speculate without evidence - say "insufficient data" when appropriate

OUTPUT FORMAT:
Always structure your response with these sections:
- VERDICT: MALICIOUS/SUSPICIOUS/CLEAN (X% confidence)
- SEVERITY: CRITICAL/HIGH/MEDIUM/LOW
- KEY FINDINGS: 3-5 bullet points
- THREAT CONTEXT: Background on threat actor/malware if known
- RECOMMENDED ACTIONS: Specific steps organized by urgency
- CONFIDENCE NOTES: What data supports/limits your assessment

IMPORTANT:
- You are analyzing security data, not the actual malware
- Never execute or simulate malicious actions
- If data is insufficient, say so rather than guessing
"""
```

Analysis prompt template:

```python
ANALYSIS_PROMPT_TEMPLATE = """
Analyze the following threat intelligence data and provide a security assessment.

INPUT TYPE: {input_type}
INPUT VALUE: {input_value}

THREAT INTELLIGENCE DATA:
{threat_intel_json}

BEHAVIORAL ANALYSIS (if available):
{behavioral_data}

ORGANIZATION CONTEXT (if available):
Industry: {org_industry}
Size: {org_size}
Critical Assets: {critical_assets}

Provide your assessment following the standard output format.
"""
```

### Response Caching

```python
class AIResponseCache:
    """Cache AI responses to reduce API costs and latency"""

    def __init__(self, cache_path: str, ttl_hours: int = 24):
        self.cache_path = cache_path
        self.ttl = ttl_hours * 3600
        self._init_db()

    def get_cache_key(self, input_hash: str, prompt_hash: str) -> str:
        """Generate cache key from input and prompt"""
        return hashlib.sha256(f"{input_hash}:{prompt_hash}".encode()).hexdigest()

    def get(self, cache_key: str) -> Optional[AIResponse]:
        """Retrieve cached response if valid"""
        pass

    def set(self, cache_key: str, response: AIResponse):
        """Store response in cache"""
        pass
```

### File Structure

```
src/secops_helper/
├── ai/
│   ├── __init__.py
│   ├── analyzer.py      # Main AI analysis orchestration
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── base.py      # AIProvider abstract base class
│   │   ├── openai.py    # OpenAI implementation
│   │   ├── anthropic.py # Anthropic Claude implementation
│   │   ├── ollama.py    # Local Ollama implementation
│   │   └── azure.py     # Azure OpenAI implementation
│   ├── prompts/
│   │   ├── __init__.py
│   │   ├── system.py    # System prompts
│   │   ├── analysis.py  # Analysis prompt templates
│   │   └── report.py    # Report generation prompts
│   ├── cache.py         # Response caching
│   └── privacy.py       # Data sanitization before sending to AI
```

## CLI Interface

### Basic Usage

```bash
# Enable AI analysis
secops analyze suspicious.eml --ai

# Quick mode (faster, less detailed)
secops analyze hash123 --ai --depth quick

# Thorough mode (slower, comprehensive)
secops analyze malware.exe --ai --depth thorough

# Specify output format
secops analyze iocs.txt --ai --format json
secops analyze iocs.txt --ai --format markdown

# Generate report
secops analyze incident_files/ --ai --report > incident_report.md
```

### Configuration

```bash
# Set AI provider
secops config set ai.provider openai          # Default
secops config set ai.provider anthropic
secops config set ai.provider ollama
secops config set ai.provider azure

# Set API key (or use environment variable)
secops config set ai.api_key sk-...
# Or: export OPENAI_API_KEY=sk-...

# Set model
secops config set ai.model gpt-4-turbo
secops config set ai.model claude-3-opus

# Local provider settings
secops config set ai.endpoint http://localhost:11434
secops config set ai.model llama3:70b

# Organization context
secops config set org.industry healthcare
secops config set org.size enterprise
secops config set org.critical_assets "patient data, EMR, billing"

# Privacy settings
secops config set ai.send_file_contents false  # Default: false
secops config set ai.send_internal_ips false   # Default: false
```

### Output Examples

**Standard Output:**
```
$ secops analyze 44d88612fea8a8f36de82e1278abb02f --ai

Analyzing hash: 44d88612fea8a8f36de82e1278abb02f
Querying threat intelligence sources... done
Running AI analysis... done

══════════════════════════════════════════════════════════════════
                      AI SECURITY ASSESSMENT
══════════════════════════════════════════════════════════════════

VERDICT: MALICIOUS (92% confidence)
SEVERITY: HIGH

Key Findings:
  • Confirmed Emotet loader (TA542) - first observed 2026-01-15
  • Detected by 45/70 AV engines on VirusTotal
  • Active C2 infrastructure at 185.234.72.x and 91.215.85.x
  • Typically delivers Cobalt Strike beacon within 24-48 hours
  • Distribution method: Malicious Excel macro via phishing

Threat Context:
  Emotet is a modular malware platform operated by TA542. After
  initial compromise, access is typically sold to ransomware
  affiliates (Conti, LockBit). Healthcare and finance sectors
  are primary targets.

  MITRE ATT&CK: T1566.001 (Phishing), T1059.001 (PowerShell),
                T1071.001 (Web C2), T1486 (Data Encrypted)

Recommended Actions:
  IMMEDIATE:
    1. Isolate affected endpoint from network
    2. Block C2 IPs at perimeter firewall:
       - 185.234.72.0/24
       - 91.215.85.0/24
    3. Search for other affected hosts (see SIEM query below)

  WITHIN 4 HOURS:
    4. Capture memory dump for forensic analysis
    5. Reset credentials for affected user
    6. Check for scheduled tasks and persistence

  SIEM Query (Splunk):
    index=firewall (dest_ip="185.234.72.*" OR dest_ip="91.215.85.*")
    | stats count by src_ip, dest_ip, dest_port

Confidence Notes:
  HIGH confidence based on:
    ✓ Hash match in MalwareBazaar with Emotet tag
    ✓ 45+ AV detections with consistent family classification
    ✓ Known C2 infrastructure still active

══════════════════════════════════════════════════════════════════
Analysis completed in 3.2s | AI tokens: 1,247 | Cache: miss
```

**JSON Output:**
```json
{
  "verdict": "MALICIOUS",
  "confidence": 0.92,
  "severity": "HIGH",
  "threat_type": "Emotet Loader",
  "threat_actor": "TA542",
  "key_findings": [
    "Confirmed Emotet loader first observed 2026-01-15",
    "Detected by 45/70 AV engines",
    "Active C2 infrastructure identified",
    "Typical precursor to ransomware deployment"
  ],
  "iocs": {
    "c2_ips": ["185.234.72.x", "91.215.85.x"],
    "c2_domains": [],
    "related_hashes": ["abc123...", "def456..."]
  },
  "mitre_attack": ["T1566.001", "T1059.001", "T1071.001"],
  "recommended_actions": [
    {
      "priority": "immediate",
      "action": "Isolate affected endpoint",
      "details": "Remove from network to prevent lateral movement"
    }
  ],
  "siem_queries": {
    "splunk": "index=firewall (dest_ip=\"185.234.72.*\"...",
    "elastic": "destination.ip: 185.234.72.* OR ..."
  },
  "metadata": {
    "analysis_time": 3.2,
    "ai_model": "gpt-4-turbo",
    "tokens_used": 1247,
    "cached": false
  }
}
```

## Non-Functional Requirements

### NFR-1: Performance
- AI analysis adds <5 seconds to standard analysis
- Cache hit rate target: >30%
- Support for async/background analysis for large batches

### NFR-2: Cost Control
- Default to most cost-effective model that meets quality bar
- Token usage tracking and alerts
- Automatic fallback to cached responses when rate limited

### NFR-3: Privacy & Security
- Never send raw file contents to cloud providers
- Support air-gapped deployment with local LLMs
- Audit log of all AI queries
- Data sanitization before transmission

### NFR-4: Reliability
- Graceful degradation if AI unavailable (return raw data only)
- Retry logic with exponential backoff
- Multiple provider support for redundancy

### NFR-5: Accuracy
- Target: <5% false positive rate on verdicts
- Confidence calibration (90% confidence should be right 90% of time)
- Regular evaluation against labeled dataset

## Testing Strategy

### Unit Tests
- Prompt template rendering
- Response parsing
- Cache operations
- Data sanitization

### Integration Tests
- End-to-end analysis with mocked AI responses
- Provider switching
- Error handling

### Quality Tests
- Evaluation dataset of 100+ labeled samples
- Measure verdict accuracy, severity accuracy
- Track confidence calibration

## Dependencies

```
# requirements.txt additions
openai>=1.0.0
anthropic>=0.5.0
ollama>=0.1.0  # Optional, for local inference
tiktoken>=0.5.0  # Token counting
```

## Configuration

```yaml
# .secops/config.yaml
ai:
  enabled: true
  provider: openai
  model: gpt-4-turbo
  api_key: ${OPENAI_API_KEY}  # Environment variable reference
  max_tokens: 2000
  temperature: 0.3
  timeout: 30
  cache_ttl_hours: 24

  # Privacy settings
  send_file_contents: false
  send_internal_ips: false
  sanitize_usernames: true

  # Cost controls
  daily_token_limit: 100000
  alert_threshold: 80000

organization:
  industry: null
  size: null
  critical_assets: []
```

## Rollout Plan

### Phase 1: Core Integration (Week 1-2)
- [ ] AI provider abstraction layer
- [ ] OpenAI integration
- [ ] Basic analysis prompt
- [ ] CLI --ai flag

### Phase 2: Enhanced Analysis (Week 3-4)
- [ ] Response caching
- [ ] Confidence scoring
- [ ] Recommended actions
- [ ] SIEM query generation

### Phase 3: Reports & Polish (Week 5-6)
- [ ] Report generation (MD, JSON)
- [ ] Multi-IOC correlation
- [ ] Organization context
- [ ] Local LLM support (Ollama)

### Phase 4: Production Hardening (Week 7-8)
- [ ] Cost controls and monitoring
- [ ] Comprehensive testing
- [ ] Documentation
- [ ] Performance optimization

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Analysis time reduction | 80% | User survey + timing logs |
| Verdict accuracy | >95% | Evaluation dataset |
| User satisfaction | >4.0/5.0 | NPS survey |
| Cache hit rate | >30% | Cache statistics |
| Cost per analysis | <$0.05 | Token tracking |

## Open Questions

1. **Default model choice**: GPT-4-turbo vs Claude 3 Opus for best security analysis?
2. **Fine-tuning**: Worth creating a fine-tuned model on security data?
3. **Threat intel integration**: Should we feed AI recent threat reports for context?
4. **Multi-language**: Support non-English reports?

## References

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic Claude Documentation](https://docs.anthropic.com)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Ollama Documentation](https://ollama.ai/docs)
