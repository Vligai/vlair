## Why

The investigation engine in `investigate/` already declares abstract connector interfaces for SIEM, EDR, Identity, and Email systems, with mock implementations for testing. The `--mock` flag is the only path that works in production — real customer environments cannot run vlair playbooks without real connectors. This change lands the first wave of production connectors with a shared retry/auth/rate-limit/audit framework so adding the next vendor is small.

## What Changes

- New `integrations/connectors/` package paralleling the abstract base in `investigate/connectors/base.py`. Each concrete vendor lives in its own module and registers under a `vendor_id` string read from configuration.
- **EDR connectors**: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint. Operations: `get_host(host_id)`, `get_processes(host_id, since)`, `isolate_host(host_id)`, `release_host(host_id)`, `run_iocfeed_check(ioc, type)`.
- **SIEM connectors**: Splunk, Microsoft Sentinel, Elastic. Operations: `search(query, time_range)`, `get_url_clicks(url, time_range)`, `get_authentication_events(user, time_range)`. Each connector accepts the dialect-native query produced by the SIEM query generator.
- **Identity connectors**: Okta, Microsoft Entra ID. Operations: `get_user(upn)`, `get_authentication_events(user, time_range)`, `disable_user(upn)`, `force_password_reset(upn)`.
- **Email connectors**: Microsoft Graph (Exchange Online), Google Workspace. Operations: `find_recipients(message_id)`, `purge_message(message_id, scope)`, `submit_to_quarantine(message_id)`.
- **Shared connector framework** (`integrations/connectors/framework.py`): retry with backoff, per-vendor rate limiting, OAuth2 token refresh, audit logging, dry-run mode (operations log what they would do but make no calls), and credential resolution via env vars or the workspace secret store.
- Configuration: per-vendor section in `~/.vlair/integrations.json`, one section per active vendor (max one per category for v1; multi-vendor per category is a follow-up). Credentials live in env vars or the workspace secret store, not the file.
- New CLI commands: `vlair connectors list`, `vlair connectors test <vendor>`, `vlair connectors status` (shows each configured connector's last successful call and any auth errors).
- New webapp endpoints: `GET /api/connectors`, `POST /api/connectors/{vendor}/test`, role-gated to `senior_analyst`.
- Phishing playbook and any future playbooks SHALL use the registry rather than calling abstract bases directly. The `--mock` flag remains supported by registering mock connectors at higher precedence when set.

## Capabilities

### New Capabilities
- `connector-framework`: shared retry, auth, rate-limit, audit, and dry-run plumbing.
- `edr-connectors`: CrowdStrike, SentinelOne, Defender for Endpoint.
- `siem-connectors`: Splunk, Sentinel, Elastic.
- `identity-connectors`: Okta, Entra ID.
- `email-connectors`: Microsoft Graph, Google Workspace.

### Modified Capabilities
- `investigation-automation`: playbooks resolve connectors from the registry; `--mock` flag still works via registry override; remediation actions go through real connectors when configured.

## Non-goals

- Multi-vendor-per-category in v1 (e.g., querying both Splunk and Sentinel from one investigation). One per category is the scope.
- IBM QRadar, Chronicle, Sumo Logic SIEM, Carbon Black, Cybereason — explicitly tracked as follow-ups under the same framework.
- Streaming / push-from-EDR (e.g., Falcon Streams API). Pull-on-demand only.
- Read-write changes to email infrastructure beyond message-level remediation (no transport rule changes, no policy changes).
- Custom field synchronization back from connectors into vlair entities. Connectors return DTOs; the engine consumes them; lifecycle stays with the source system.
- Cortex XSOAR or other SOAR integrations. vlair stays a focused engine; SOAR coexistence is a future capability.

## Impact

- **Code**: new `src/vlair/integrations/connectors/` package; modifications to `investigate/engine.py` (registry resolution), `investigate/playbooks/phishing.py` (use real connectors), `cli/main.py` (new subcommand group), `webapp/app.py` (new endpoints).
- **Schema**: new `connector_status` table tracking last successful/failed call per connector; `audit_log` gains structured `connector` and `vendor` fields.
- **Dependencies**: optional extras `[crowdstrike]` (`crowdstrike-falconpy`), `[sentinelone]` (`sentinelone-sdk`), `[defender]` (`msgraph-sdk`), `[splunk]` (`splunk-sdk`), `[sentinel]` (`azure-monitor-query`), `[elastic]` (`elasticsearch>=8`), `[okta]` (`okta`), `[entra]` (`msgraph-sdk` shared with defender), `[gws]` (`google-api-python-client`).
- **Tests**: per-vendor mocked-API test files; framework-level tests for retry/backoff, rate limiting, OAuth refresh, and audit emission.
- **Docs**: new `docs/CONNECTORS.md` covering setup recipes per vendor; `docs/DEPLOYMENT.md` updated for credential storage; `docs/INVESTIGATION.md` updated to remove "mock-only in prod" caveat.
