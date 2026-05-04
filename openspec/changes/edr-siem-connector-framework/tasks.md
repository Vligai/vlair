## 1. Framework foundation

- [ ] 1.1 Create `src/vlair/integrations/connectors/__init__.py` and `framework.py` with `BaseConnector`, `ConnectorConfig`, `OAuth2TokenManager`, `RateLimiter`
- [ ] 1.2 Category subclasses: `EDRConnector`, `SIEMConnector`, `IdentityConnector`, `EmailConnector`
- [ ] 1.3 `registry.py`: discover and resolve concrete connectors per category
- [ ] 1.4 Typed exceptions: `ConnectorError`, `ConnectorNotConfiguredError`, `AuthenticationError`, `RateLimitError`, `InvalidTimeRangeError`
- [ ] 1.5 Tests: registry resolution; OAuth refresh on 401; backoff schedule; token never serialized

## 2. Configuration loader

- [ ] 2.1 Extend `~/.vlair/integrations.json` schema with `connectors` section; loader merges with `threat_platform` config from prior change
- [ ] 2.2 Env var resolution; rate-limit override; per-vendor verify_ssl
- [ ] 2.3 Tests: malformed config; partial config (only some categories); env-only credentials

## 3. Schema and audit

- [ ] 3.1 Migration: create `connector_status` table
- [ ] 3.2 Audit log: add `vendor`, `category`, `operation`, `latency_ms` structured fields
- [ ] 3.3 Credential redaction in audit (regex-based) with unit test asserting no token-shaped strings

## 4. Mock registration

- [ ] 4.1 `--mock=<categories>` plumbing in CLI and engine
- [ ] 4.2 Mock connectors for all four categories preserved and now registered via the registry
- [ ] 4.3 Mixed-mode tests: mock EDR + real SIEM

## 5. SIEM: Splunk first

- [ ] 5.1 `splunk.py`: `SplunkConnector` using `splunk-sdk`
- [ ] 5.2 `[splunk]` extra in pyproject
- [ ] 5.3 Time range normalization helper
- [ ] 5.4 Mocked-API tests using `splunk-sdk` test doubles
- [ ] 5.5 Manual integration checklist for Splunk

## 6. EDR: CrowdStrike first

- [ ] 6.1 `falcon.py`: `FalconConnector` using `crowdstrike-falconpy`
- [ ] 6.2 `[crowdstrike]` extra
- [ ] 6.3 OAuth2 client_credentials wired through framework token manager
- [ ] 6.4 Mocked-API tests
- [ ] 6.5 Manual integration checklist for CrowdStrike

## 7. Identity: Okta first

- [ ] 7.1 `okta.py`: `OktaConnector` using the `okta` SDK
- [ ] 7.2 `[okta]` extra
- [ ] 7.3 Mocked-API tests; user lookup, sign-in events, disable

## 8. Email: Microsoft Graph first

- [ ] 8.1 `graph_mail.py`: `GraphMailConnector` using `msgraph-sdk`
- [ ] 8.2 `[graph]` extra
- [ ] 8.3 Find recipients, purge, quarantine
- [ ] 8.4 Mocked-API tests

## 9. Phishing playbook migration

- [ ] 9.1 Replace direct connector construction with `registry.resolve(category)`
- [ ] 9.2 Step-level try/except for `ConnectorError`; degraded-data flag in result
- [ ] 9.3 Per-investigation connector overrides plumbed
- [ ] 9.4 Tests: real-connector mode (mocked APIs); mixed mode; full-mock mode parity

## 10. Remaining vendors (per-vendor PRs)

- [ ] 10.1 SentinelOne (`sentinelone.py`, `[sentinelone]` extra)
- [ ] 10.2 Defender for Endpoint (`defender.py`, `[defender]` extra)
- [ ] 10.3 Microsoft Sentinel (`sentinel.py`, `[sentinel]` extra)
- [ ] 10.4 Elastic (`elastic.py`, `[elastic]` extra)
- [ ] 10.5 Microsoft Entra ID (`entra.py`, `[entra]` extra)
- [ ] 10.6 Google Workspace (`google_workspace.py`, `[gws]` extra)

## 11. CLI

- [ ] 11.1 `vlair connectors list` (shows configured + available)
- [ ] 11.2 `vlair connectors test <category|all> [--refresh]`
- [ ] 11.3 `vlair connectors status`
- [ ] 11.4 Tests: each subcommand happy path + error path

## 12. Webapp

- [ ] 12.1 `GET /api/connectors` (returns configured connectors and their status)
- [ ] 12.2 `POST /api/connectors/{category}/test` (senior_analyst)
- [ ] 12.3 SPA: connectors page with status indicators per category
- [ ] 12.4 Tests: role gating; status reflects last call

## 13. Documentation

- [ ] 13.1 New `docs/CONNECTORS.md` with per-vendor setup recipes
- [ ] 13.2 Update `docs/INVESTIGATION.md`: drop "mock-only in production" caveat
- [ ] 13.3 Update `docs/DEPLOYMENT.md`: credential storage recommendations
- [ ] 13.4 Update `docs/INDEX.md` with connector commands
