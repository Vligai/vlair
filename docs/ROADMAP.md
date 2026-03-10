# vlair - Roadmap & Future Enhancements

**Last Updated:** February 26, 2026
**Current Version:** 5.0.0
**Status:** Phase 5 in progress (API complete, frontend pending)

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

## Phase 5: Web Interface (Q1 2026)

**Overall Status:** ✅ Complete — API, auth, and Vue 3 SPA all done

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

**Status:** ✅ Complete (6.1–6.4 core features done; 6.5 planned)
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

### 6.5 Conversational Security Assistant
- Slack/Teams bot integration
- Interactive investigation follow-up questions
- Security concept explainer for junior analysts

---

## Phase 7: Enterprise Features (Q3 2026)

**Status:** Planned

- Multi-tenancy with isolated data per organization
- SIEM integrations (Splunk, ELK, MISP, Webhooks/syslog CEF)
- Report generation engine (executive PDF, technical HTML, compliance)
- Advanced caching (multi-tier: browser/CDN/Redis/DB)

---

## Phase 8: Advanced Threat Intelligence (Q4 2026)

**Status:** Planned

- Threat actor tracking and attribution (APT1, Lazarus, etc.)
- Dark web monitoring (Tor, paste sites, breach databases)
- Feed quality scoring and curation
- Geopolitical threat context

---

## Phase 9: Mobile & API Ecosystem (Q1 2027)

**Status:** Future

- iOS/Android app (React Native) — quick IOC lookups, push alerts
- Public RESTful API with rate limiting, GraphQL, WebSocket
- SDK libraries (Python, JavaScript, Go)

---

## Implementation Priorities

### Now (Phase 5 remaining)
- [ ] Build Vue.js 3 frontend (5.3)

### Q2 2026 (Phase 6)
- [ ] AI-assisted IOC analysis and summarization
- [ ] Malware classification ML models
- [ ] Automated playbook generation
- [ ] Conversational assistant (Slack/Teams bot)

### Q3 2026 (Phase 7)
- [ ] Multi-tenancy
- [ ] SIEM integrations
- [ ] Report generation engine

### Q4 2026 (Phase 8)
- [ ] Threat actor tracking
- [ ] Dark web monitoring
- [ ] Feed curation engine

---

## Current Technology Stack

| Layer | Current | Target (Phase 7+) |
|-------|---------|-------------------|
| Backend | Python 3.9–3.11, Flask | Python 3.12+, Flask + FastAPI |
| Database | SQLite | PostgreSQL 16+ + Neo4j (graph) |
| Cache | Redis (optional) | Multi-tier (browser/CDN/Redis/DB) |
| Frontend | None (API-only) | Vue.js 3 + TypeScript + Vite |
| AI/ML | — | Claude API, scikit-learn, PyTorch |
| Testing | pytest, 32 test files, >80% coverage | 500+ tests, >85% coverage |
| CI/CD | GitHub Actions | GitHub Actions + ArgoCD |
| Deployment | Docker, docker-compose | Kubernetes (prod), Docker Compose (dev) |
| Monitoring | — | Prometheus, Grafana, Sentry |

---

## Key Metrics & Success Criteria

### Performance
- API latency: p95 < 500ms
- Uptime: 99.9% availability

### AI (Phase 6)
- Threat summary accuracy: >90% (human evaluation)
- Malware classification: >95% on test set
- False positive reduction: 50% vs baseline

### Adoption (long-term)
- 1,000 active users by EOY 2026
- 10 enterprise customers

---

## Risks & Mitigation

| Risk | Mitigation |
|------|-----------|
| AI API costs | Caching, prompt optimization, rate limiting |
| Scalability | Horizontal scaling, DB sharding |
| Model accuracy | Continuous retraining, human-in-the-loop |
| API rate limits | Multi-source redundancy, premium tiers |
| Compliance | GDPR/SOC 2 from day one, regular audits |

---

## Long-Term Vision (2027+)

**Mission:** De facto open-source security operations platform

1. AI handles 80% of L1 SOC analyst tasks
2. Real-time global threat sharing across users
3. Predictive defense — forecast attacks before they happen
4. Enterprise SaaS offering alongside open-source

---

## Next Steps

1. ✅ ~~Complete web API endpoints~~ (all 13 endpoints done)
2. ✅ ~~Implement authentication & RBAC~~ (JWT, TOTP MFA, RBAC, audit log)
3. ✅ ~~Build Vue.js 3 frontend~~ (Phase 5.3 complete — Vue 3 CDN SPA)
4. ✅ ~~Begin AI integration~~ (Phase 6.1 — Claude summaries in all tool panels)
5. Continue Phase 6: natural language queries, ML malware classification

---

**Document Maintainer:** Vligai
**Last Updated:** February 26, 2026
**Next Review:** May 1, 2026
