# vlair - Roadmap & Future Enhancements

**Last Updated:** March 13, 2026
**Current Version:** 5.0.0
**Status:** Phase 6.1–6.4 complete; 6.5 in progress

---

## Completed Phases

### Phase 1: Email & Basic IOC Analysis ✅
- **EML Parser** - Email threat analysis with VirusTotal integration
- **IOC Extractor** - Extract IPs, domains, URLs, emails, hashes, CVEs
- **Hash Lookup** - Multi-source file hash intelligence (VT, MalwareBazaar)
- **Domain/IP Intelligence** - Network threat intelligence with risk scoring

### Phase 2: Log & Network Analysis ✅
- **Log Analyzer** - Apache/Nginx/Syslog parsing with attack detection
- **PCAP Analyzer** - Network traffic analysis with protocol inspection
- **URL Analyzer** - URL threat analysis with pattern detection

### Phase 3: Advanced Malware & Forensics ✅
- **YARA Scanner** - Multi-format malware scanning with custom rules
- **Certificate Analyzer** - SSL/TLS certificate analysis and phishing detection
- **Script Deobfuscator** - Multi-language deobfuscation (JS, PowerShell, VBScript, Batch)
- **Threat Feed Aggregator** - Multi-source threat intelligence aggregation (ThreatFox, URLhaus)
- **File Carver** - Forensic file extraction from disk images and memory dumps

### Phase 4: Operationalization ✅
- **Unified `vlair` CLI** - Single entry point for all 12 tools with smart auto-detection
- **`vlair analyze`** - Auto-detects input type, runs appropriate tools, returns risk score + verdict
- **`vlair check`** - Quick single-indicator lookup (hash/domain/ip/url)
- **`vlair workflow`** - 5 pre-built investigation workflows (phishing, malware triage, IOC hunt, network forensics, log investigation)
- **`vlair investigate`** - Investigation automation engine with playbooks, SQLite state persistence, connector framework
- **`vlair shell`** - Interactive REPL (command history, per-command help)
- **`vlair status`** - API key status, cache stats, recent history
- **Testing** - 32 test files, >80% coverage
- **CI/CD** - GitHub Actions (Python 3.9/3.10/3.11), Docker, docker-compose
- **Common Modules** - Redis caching, STIX 2.1 export

---

## Phase 5: Web Interface ✅ Complete

**Overall Status:** Complete — API, auth, and Vue 3 SPA all done

### 5.1 Web API — All 12 Tools ✅ Complete

All tool endpoints implemented in `src/vlair/webapp/app.py`:

| Endpoint | Tool | Min Role |
|----------|------|----------|
| `POST /api/ioc/extract` | IOC Extractor | analyst |
| `POST /api/hash/lookup` | Hash Lookup | analyst |
| `POST /api/intel/analyze` | Domain/IP Intel | analyst |
| `POST /api/url/analyze` | URL Analyzer | analyst |
| `POST /api/log/analyze` | Log Analyzer | analyst |
| `POST /api/eml/parse` | EML Parser | analyst |
| `POST /api/yara/scan` | YARA Scanner | analyst |
| `POST /api/cert/analyze` | Cert Analyzer | analyst |
| `POST /api/deobfuscate` | Deobfuscator | analyst |
| `POST /api/pcap/analyze` | PCAP Analyzer | analyst |
| `POST /api/threatfeed/search` | Threat Feeds | analyst |
| `POST /api/threatfeed/update` | Threat Feeds | senior_analyst |
| `POST /api/carve/extract` | File Carver | senior_analyst |

### 5.2 Authentication & Authorization ✅ Complete

Full auth system in `src/vlair/webapp/auth/`:

- **User accounts** — SQLite-backed, PBKDF2-SHA256 passwords
- **JWT tokens** — Access (15 min) + Refresh (7 days), no external deps fallback
- **RBAC** — Viewer / Analyst / Senior Analyst / Admin
- **TOTP MFA** — Optional setup/verify/disable (via `pyotp`)
- **API keys** — SHA-256 hashed, prefix for display, per-user, expiry support
- **Audit log** — Immutable SQLite record of every authenticated action
- **Admin endpoints** — User management, role changes, activate/deactivate
- **Configurable registration** — Open or admin-only (`VLAIR_OPEN_REGISTRATION`)

Auth endpoint reference:

```
POST   /api/auth/register          - Create account
POST   /api/auth/login             - Get access + refresh tokens
POST   /api/auth/refresh           - Renew access token
POST   /api/auth/logout            - Revoke session
GET    /api/auth/me                - Current user profile
PUT    /api/auth/me/password       - Change password
POST   /api/auth/mfa/setup         - Initiate TOTP enrollment
POST   /api/auth/mfa/verify        - Enable MFA after verifying code
DELETE /api/auth/mfa               - Disable MFA
POST   /api/auth/keys              - Create API key
GET    /api/auth/keys              - List API keys
DELETE /api/auth/keys/<id>         - Revoke API key
GET    /api/admin/users            - List users (admin)
PUT    /api/admin/users/<id>/role  - Change role (admin)
GET    /api/admin/audit            - Audit log (senior_analyst+)
```

Environment variables:

```
VLAIR_SECRET_KEY         JWT signing secret (required in production)
VLAIR_WEBAPP_DB          SQLite DB path (default: ~/.vlair/webapp.db)
VLAIR_OPEN_REGISTRATION  true/false — allow self-registration (default: true)
VLAIR_ACCESS_TTL         Access token lifetime in seconds (default: 900)
VLAIR_REFRESH_TTL        Refresh token lifetime in seconds (default: 604800)
ANTHROPIC_API_KEY        Anthropic API key (required for /api/ai/summarize)
```

### 5.3 Modern Frontend ✅ Complete

**Implemented:** Vue 3 CDN SPA (no build step) with Chart.js charts and MFA UI

**Technology Stack:**
- **Frontend:** Vue.js 3 (CDN, no build step)
- **Charts:** Chart.js (CDN)
- **Auth:** JWT + TOTP MFA setup/disable UI

**Key Views implemented:**
1. **Dashboard** — Overview, stats, quick-action tool cards
2. **Tools** — All 13 tools with per-tool structured result rendering
3. **Profile** — Change password, MFA setup/disable, API key management
4. **Administration** — User management, role changes, audit log

---

## Phase 6: AI-Powered Analysis (Q2 2026)

**Status:** 6.1–6.4 complete; 6.5 in progress
**Priority:** HIGH

### 6.1 AI-Assisted IOC Analysis ✅ Complete
- ✅ Claude-powered executive summaries (`/api/ai/summarize`, `vlair analyze --ai`)
- ✅ MITRE ATT&CK technique mapping
- ✅ Verdict + severity + key findings + recommended actions
- ✅ SQLite-backed persistent cache with token tracking (`~/.vlair/ai_cache.db`)
- ✅ "AI Analysis" button in all tool result panels
- ✅ `vlair analyze <input> --ai` CLI flag
- ✅ `--depth quick|standard|thorough`
- ✅ AI result embedded in `--json` as `ai_analysis` key
- ✅ **Provider abstraction layer** — Anthropic, OpenAI, Ollama (local) support
- ✅ **`vlair ai-stats`** — request count, token usage, cost estimate, cache hit rate
- ✅ **`--dry-run`** flag — preview what would be sent to AI before calling
- ✅ **`--report ai-markdown`** — full Markdown investigation report
- ✅ **Privacy controls** — sanitizes RFC-1918 IPs, file contents before cloud API calls

**Required:** `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`, or local Ollama)

**Technology:** Claude API (Anthropic), OpenAI GPT-4, Ollama (local LLMs)

### 6.2 Malware Classification ✅ Complete (heuristic)
- ✅ `MalwareClassifier` — heuristic rule-based classifier (20+ malware families)
- ✅ Classifies Emotet, Cobalt Strike, QakBot, TrickBot, Ryuk, LockBit, Conti, Mimikatz, etc.
- ✅ Confidence scoring, MITRE technique mapping, threat actor attribution

**Module:** `src/vlair/ai/classifier.py`

### 6.3 Automated Playbook Generation ✅ Complete
- ✅ `PlaybookGenerator` — generates IR playbooks via Claude or built-in heuristic templates
- ✅ `vlair ai playbook phishing|ransomware|c2|data_exfil` — step-by-step IR plans
- ✅ SIEM queries (Splunk + Elastic) included in output
- ✅ Graceful fallback to heuristic templates when AI unavailable

**Module:** `src/vlair/ai/playbook_generator.py`

### 6.4 Intelligent Threat Hunting ✅ Complete (IOC Correlation)
- ✅ `IOCCorrelator` — cross-IOC campaign pattern detection
- ✅ Threat actor attribution from correlated IOC signals
- ✅ Relationship mapping between IOCs (shared infra, same malware family)
- ✅ SIEM query generation (in `--depth thorough` AI mode)

**Module:** `src/vlair/ai/correlator.py`

### 6.5 Conversational Security Assistant (In Progress)

Slack and Microsoft Teams bot that brings vlair's AI analysis directly into the channels analysts already work in.

**Goals:**
- Run vlair tools and get AI summaries without leaving Slack/Teams
- Follow-up questions on any analysis result in-thread
- Security concept explainer for junior analysts
- Works with any vlair instance (self-hosted or otherwise) via webhook

**Components:**

#### Slack Bot

**@mention commands (primary interface)** — work in any channel or thread:
- `@vlair analyze <hash|domain|ip|url>` — auto-detects type, runs tool, posts summary
- `@vlair investigate <free text>` — natural language; extracts IOCs from the message/thread and kicks off an investigation
- `@vlair workflow phishing` — starts phishing workflow using attachments or URLs in the current thread
- `@vlair explain <term or finding>` — security concept explainer, replies in-thread
- `@vlair ask <question>` — free-form AI question with context from the thread above
- `@vlair summary` — summarizes all findings posted in the current thread

Thread-awareness: when triggered inside a thread, vlair reads the full thread history as context before responding.

**Slash commands (utility / DM-friendly):**
- `/vlair status` — show API key health, cache stats, recent investigations
- `/vlair help` — list available commands

**Interactive elements:**
- Buttons on every result card: "Deeper Analysis", "Generate SIEM Query", "Export IOCs"
- Overflow menu: "Open in web UI", "Share to channel", "Create investigation"

#### Microsoft Teams Bot
- Same command surface as the Slack bot via Teams messaging extensions
- Adaptive Cards for structured result display (verdict badge, risk score, key findings)
- `/vlair` command in any channel or DM

#### Backend — Bot Webhook Server
- Lightweight Flask handler in `src/vlair/integrations/slack.py` / `teams.py`
- Verifies request signatures (Slack signing secret / Teams HMAC)
- Routes commands to existing vlair tools and AI layer
- Stores per-channel conversation context in SQLite (`~/.vlair/bot.db`)
- Rate limiting per user (configurable, default 20 req/hour)

#### Natural Language Capabilities
- Explain results: "what does this YARA hit mean for triage priority?"
- Generate artifacts: "write a Splunk query to hunt for this C2 IP"
- Summarize multiple results: "compare these two hash lookups"
- Fallback to static playbook templates when AI is unavailable

**Configuration:**
```
VLAIR_SLACK_BOT_TOKEN       Slack bot OAuth token
VLAIR_SLACK_SIGNING_SECRET  Slack signing secret (for request verification)
VLAIR_TEAMS_APP_ID          Teams app ID
VLAIR_TEAMS_APP_PASSWORD    Teams app password
VLAIR_BOT_RATE_LIMIT        Requests per hour per user (default: 20)
```

**Running the bot server:**
```bash
vlair bot slack    # Start Slack event listener on port 3000
vlair bot teams    # Start Teams bot on port 3978
```

---

## Phase 7: Integrations & Reporting (Q3 2026)

**Status:** Planned
**Focus:** Connect vlair to the tools analysts already use; make output shareable

### 7.1 SIEM Integrations
- **Splunk** — push findings as notable events, pull raw search results into vlair
- **Elastic/OpenSearch** — index investigation results, query via vlair CLI
- **Syslog / CEF** — forward alerts to any SIEM over UDP/TCP syslog
- **Webhooks** — POST findings to any URL (generic integration for SOAR tools)
- **MISP** — push IOCs as MISP events, pull threat intel from your MISP instance

All integrations are optional and configured via `.env` / environment variables. No cloud account required.

```
VLAIR_SPLUNK_URL          Splunk HEC endpoint
VLAIR_SPLUNK_TOKEN        Splunk HEC token
VLAIR_ELASTIC_URL         Elasticsearch URL
VLAIR_MISP_URL            MISP instance URL
VLAIR_MISP_KEY            MISP API key
VLAIR_WEBHOOK_URL         Generic webhook endpoint
```

### 7.2 Report Generation
- **HTML report** — self-contained single-file report (no CDN deps, works offline)
- **Markdown report** — suitable for paste into Confluence, Notion, GitHub Issues
- **PDF export** — via headless Chromium or WeasyPrint (optional dep)
- **`vlair report generate <investigation-id>`** — generate report from stored investigation
- **`vlair report open`** — open last report in default browser
- Templates: Executive Summary, Technical Deep-Dive, IOC Digest

### 7.3 Caching Layer
- **Redis** (optional) — shared cache for multi-user deployments; falls back to SQLite if unavailable
- **SQLite** (default) — zero-config, works for single-user or small team installs
- Cache scopes: API responses (VT, AbuseIPDB), AI summaries, SIEM query results
- `vlair cache stats` — hit rate, size, oldest entry
- `vlair cache clear [--scope api|ai|siem]` — selective purge

---

## Phase 8: Advanced Threat Intelligence (Q4 2026)

**Status:** Planned

- Threat actor tracking and attribution (APT1, Lazarus, etc.)
- Dark web monitoring (Tor, paste sites, breach databases)
- Feed quality scoring and curation
- Geopolitical threat context

---

## Phase 9: Ecosystem & Automation (Q1 2027)

**Status:** Future

- Public RESTful API with rate limiting
- SDK libraries (Python, JavaScript, Go) for automation scripts
- n8n / Zapier / Make.com integration nodes
- iOS/Android quick-lookup companion app

---

## Implementation Priorities

### Now (Phase 6.5)
- [ ] Slack bot command handler (`/vlair analyze`, `/vlair ask`, `/vlair workflow`)
- [ ] Teams bot with Adaptive Cards
- [ ] Bot webhook server (`vlair bot slack|teams`)
- [ ] Per-channel conversation context (SQLite `bot.db`)
- [ ] Interactive buttons / follow-up thread replies

### Q3 2026 (Phase 7)
- [ ] SIEM push integrations (Splunk HEC, Elastic, syslog/CEF)
- [ ] MISP IOC sync
- [ ] Report generation (HTML + Markdown; PDF optional)
- [ ] Redis cache with SQLite fallback

### Q4 2026 (Phase 8)
- [ ] Threat actor tracking
- [ ] Dark web monitoring
- [ ] Feed curation engine

---

## Current Technology Stack

| Layer | Current | Target (Phase 7+) |
|-------|---------|-------------------|
| Backend | Python 3.9–3.11, Flask | Python 3.12+, Flask + async endpoints |
| Database | SQLite | SQLite (default) + PostgreSQL (optional, large installs) |
| Cache | Redis (optional) + SQLite | Redis (optional) + SQLite fallback |
| Frontend | Vue.js 3 CDN SPA | Vue.js 3 CDN SPA + WebSocket chat |
| AI/ML | Claude API, OpenAI, Ollama | Same — provider abstraction maintained |
| Testing | pytest, 32 test files, >80% coverage | 500+ tests, >85% coverage |
| CI/CD | GitHub Actions | GitHub Actions |
| Deployment | Docker, docker-compose | Docker Compose (primary); single-binary option planned |
| Monitoring | — | Optional Prometheus endpoint + log file |

**Self-hosting philosophy:** vlair should run on a single machine with `docker-compose up` or `pip install && vlair serve`. No managed cloud services required. SQLite is the default for everything; Redis and PostgreSQL are optional scale-up paths.

---

## Key Metrics & Success Criteria

### Performance
- API latency: p95 < 500ms
- Chat streaming: first token < 2s

### AI (Phase 6)
- Threat summary accuracy: >90% (human evaluation)
- Malware classification: >95% on test set
- False positive reduction: 50% vs baseline

### Adoption
- Self-hosted installs: 500+ by EOY 2026
- Active GitHub contributors: 10+

---

## Risks & Mitigation

| Risk | Mitigation |
|------|-----------|
| AI API costs | Caching, `--dry-run`, Ollama local fallback |
| Model accuracy | Heuristic fallbacks, human-review prompts |
| API rate limits | Multi-source redundancy, per-user rate limiting |
| Self-host complexity | Single docker-compose.yml, sane defaults, no required cloud deps |

---

## Long-Term Vision (2027+)

**Mission:** The go-to open-source security operations toolkit that any analyst can self-host in minutes

1. AI handles 80% of L1 triage tasks
2. Pluggable integrations for any SIEM/SOAR/ticketing system
3. Active community of playbooks and YARA rules
4. Works fully offline with local LLMs (Ollama)

---

## Next Steps

1. ✅ ~~Complete web API endpoints~~ (all 13 endpoints done)
2. ✅ ~~Implement authentication & RBAC~~ (JWT, TOTP MFA, RBAC, audit log)
3. ✅ ~~Build Vue.js 3 frontend~~ (Phase 5.3 complete — Vue 3 CDN SPA)
4. ✅ ~~Begin AI integration~~ (Phase 6.1–6.4 complete)
5. **Now:** Phase 6.5 — Slack/Teams bot (`vlair bot slack|teams`)

---

**Document Maintainer:** Vligai
**Last Updated:** March 13, 2026
**Next Review:** June 1, 2026
