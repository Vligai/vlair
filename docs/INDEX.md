# vlair Docs Index

> Token-optimized quick reference. Full details in linked files.

**Version:** 5.0.0 | **Status:** Phase 5 (Operationalization) complete | **Python:** 3.9+

---

## What is vlair

Unified CLI security operations toolkit. 12 tools under one `vlair` command with smart auto-detection, pre-built workflows, and actionable output (risk score 0-100, verdict, recommended actions).

**Install:** `pip install -e .` | **Entry point:** `vlair` command

---

## Source Layout

```
src/vlair/
├── cli/          main.py (primary), shell.py (REPL), legacy.py
├── core/         analyzer.py, detector.py, scorer.py, reporter.py,
│                 workflow.py, interactive.py, report_generator.py, history.py
├── tools/        12 security tools (see table below)
├── workflows/    phishing_email, malware_triage, ioc_hunt,
│                 network_forensics, log_investigation
├── investigate/  engine.py, state.py, registry.py, playbooks/, connectors/
├── common/       cache_manager.py (Redis), stix_export.py
├── data/         yara_rules/
└── webapp/       Flask API (all 12 tools) + auth (JWT/TOTP/RBAC) — no frontend yet
tests/            test_*.py — >80% coverage target
docs/             INDEX.md (this), CONTRIBUTING.md, ROADMAP.md, openspec/
```

---

## Tools

| Command | File | Purpose |
|---------|------|---------|
| `eml` | tools/eml_parser.py | Email headers, SPF/DKIM/DMARC, attachments |
| `ioc` | tools/ioc_extractor.py | Extract IPs/domains/URLs/hashes/CVEs from text |
| `hash` | tools/hash_lookup.py | VirusTotal + MalwareBazaar file hash lookup |
| `intel` | tools/domain_ip_intel.py | DNS, reputation, threat intel for domains/IPs |
| `log` | tools/log_analyzer.py | Apache/Nginx/syslog — SQLi, XSS, brute-force |
| `pcap` | tools/pcap_analyzer.py | Network traffic, port scan, DGA detection |
| `url` | tools/url_analyzer.py | URL reputation, 11 suspicious pattern checks |
| `yara` | tools/yara_scanner.py | YARA malware scanning, multi-threaded |
| `cert` | tools/cert_analyzer.py | SSL/TLS cert security and phishing checks |
| `deobfuscate` | tools/deobfuscator.py | JS/PowerShell/VBScript/Batch deobfuscation |
| `feeds` | tools/threat_feed_aggregator.py | ThreatFox + URLhaus IOC aggregation |
| `carve` | tools/file_carver.py | Extract files from disk images/memory dumps |

---

## CLI Quick Reference

```bash
# Smart analysis (auto-detects type)
vlair analyze <file|hash|domain|ip|url>  [--verbose] [--json] [--quiet]
vlair analyze <input> --ai               # + Claude AI assessment
vlair analyze <input> --ai --depth thorough  # deep analysis with SIEM queries

# Quick single-indicator check
vlair check hash <hash>
vlair check domain <domain>
vlair check ip <ip>
vlair check url <url>

# Workflows
vlair workflow phishing-email <file>
vlair workflow malware-triage <file>
vlair workflow ioc-hunt <file>
vlair workflow network-forensics <file>
vlair workflow log-investigation <file>

# Investigation automation
vlair investigate phishing --file <eml> [--mock]
vlair investigate status <INV-ID>
vlair investigate list [--limit N]
vlair investigate results <INV-ID> [--json]

# Individual tools
vlair eml|ioc|hash|intel|log|pcap|url|yara|cert|deobfuscate|feeds|carve <args>

# Utility
vlair shell          # Interactive REPL
vlair list           # All tools with status
vlair status         # API keys, cache, history
```

**Exit codes:** 0=Clean, 1=Suspicious, 2=Malicious, 3=Error

---

## Configuration (.env)

```
VT_API_KEY=            # VirusTotal (4 req/min free) — eml, hash, intel, url
ABUSEIPDB_KEY=         # AbuseIPDB (free tier) — intel
REDIS_URL=             # Optional; falls back to in-memory cache

# AI summaries (vlair analyze --ai)
ANTHROPIC_API_KEY=     # Required for Claude-powered threat summaries
VLAIR_AI_PROVIDER=     # anthropic (default) | openai | ollama
ANTHROPIC_MODEL=       # Override model (default: claude-sonnet-4-6)
```

---

## AI / Token Optimization (Beskar)

vlair's `AnthropicProvider` wraps [`beskar`](https://github.com/Vligai/beskar) when installed — a token optimization layer for the Anthropic SDK.

**What it does:**
- **Prompt caching** — attaches `cache_control: ephemeral` to the large, stable system prompts used per IOC type. Repeated analyses of the same type (e.g., multiple hashes in one session) cut input costs by ~90% on the cached portion.
- **Token metrics** — tracks cumulative `cache_hit_rate`, `estimated_cost_usd`, and `estimated_savings_usd` across all AI calls in a session.

**Install beskar** (local checkout):
```bash
pip install -e /path/to/beskar
pip install -e ".[ai]"
```

**Access metrics programmatically:**
```python
from vlair.ai.providers.anthropic import AnthropicProvider
provider = AnthropicProvider()
provider.analyze(system_prompt, user_message)
metrics = provider.get_metrics()  # MetricsSummary or None if beskar not installed
# MetricsSummary.cache_hit_rate, .estimated_cost_usd, .estimated_savings_usd
```

**AI response metadata** — each `ThreatSummarizer.summarize()` result now includes:
```json
"metadata": {
  "tokens_used": 542,
  "cache_read_tokens": 480,
  "cache_creation_tokens": 0,
  ...
}
```

Beskar is **optional** — if not installed, `AnthropicProvider` falls back transparently to plain `anthropic.Anthropic`.

**Key files:**
- `src/vlair/ai/providers/anthropic.py` — BeskarClient integration + `get_metrics()`
- `src/vlair/ai/providers/base.py` — `AIResponse.cache_read_tokens` / `cache_creation_tokens`
- `src/vlair/ai/summarizer.py` — cache token counts in response metadata

---

## Key Patterns & Conventions

- **Formatting:** `black` (line length 127) — required before commit
- **Linting:** `flake8 --max-line-length=127`
- **Tests:** `pytest tests/ -v` | mock all external APIs
- **Imports:** `from vlair.tools.hash_lookup import X`
- **Output:** JSON default; always include `metadata`, `summary`, `results` keys
- **Error exit:** `sys.exit(1)` with message to stderr
- **API keys:** `os.getenv()` only, never logged or committed

---

## Implementation Status

| Feature | Status |
|---------|--------|
| 12 security tools | ✅ Done |
| Smart `analyze` command | ✅ Done |
| `vlair check` quick lookup | ✅ Done |
| Pre-built workflows (5) | ✅ Done |
| Interactive `investigate` mode | ✅ Done |
| Investigation automation engine | ✅ Done |
| Phishing investigation playbook | ✅ Done |
| Flask API (all 12 tools) | ✅ Done |
| Auth (JWT, TOTP MFA, RBAC, API keys, audit) | ✅ Done |
| Web frontend (Vue.js 3) | ✅ Done (Vue 3 CDN SPA) |
| AI summaries — web API (`/api/ai/summarize`) | ✅ Done |
| AI summaries — CLI (`vlair analyze --ai`) | ✅ Done |
| Beskar token optimization (prompt caching + metrics) | ✅ Done |
| Enterprise / SIEM integration (Phase 7+) | ❌ Not started |

Operationalize spec: `docs/openspec/specs/operationalize.spec.md`

---

## Detailed Docs

| Doc | Contents |
|-----|----------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, code quality, PR process, CI/CD |
| [ROADMAP.md](ROADMAP.md) | Phases 5–10, timelines, tech stack evolution |
| [openspec/project.openspec.md](openspec/project.openspec.md) | Project-level OpenSpec |
| [openspec/specs/](openspec/specs/) | 17 individual tool specs (FR-1…FR-15 each) |
| [../README.md](../README.md) | User-facing install/usage guide |
| [../CLAUDE.md](../CLAUDE.md) | Full AI assistant guide (authoritative) |
