## Context

The phishing playbook in `investigate/playbooks/phishing.py` already calls connector methods like `siem.find_url_clicks(...)` and `email.find_recipients(...)`. Today these resolve to mock implementations — the production-only path doesn't exist. This change is the production path.

The investigation-engine connectors are abstract DTOs-and-methods, decoupled from any vendor. That decoupling is the right shape; we just need to fill it in. The question is how much shared plumbing to put around the per-vendor implementations versus letting each connector handle its own retries, rate limits, and auth.

The natural shape: a thin shared framework (auth, retry, rate-limit, audit, dry-run) wrapping a vendor-specific client (which we typically don't write — vendors ship their own SDK). Pretty much every vendor SDK in scope is OAuth2 with token refresh, request/response, and the same set of failure modes (401 → refresh, 429 → backoff, 5xx → retry). So this is one base class doing the same job nine ways for nine vendors, with the per-vendor module thin.

## Goals / Non-Goals

**Goals:**
- One connector per category (EDR/SIEM/Identity/Email) configured per workspace; the playbook engine resolves connectors via a registry.
- Production parity with mock: every operation the mock supports is supported by at least one real connector.
- Failure isolation: a connector that's down or misconfigured doesn't block the engine; the affected step records "connector unavailable" and the investigation continues with degraded findings.
- Dry-run for write operations: `vlair investigate --dry-run` invokes connectors but they log what they would do without making the API write.
- Audit symmetry: every call is logged with vendor, operation, target, outcome, and latency.

**Non-Goals:**
- Multi-vendor-per-category (federated SIEM search). One vendor at a time.
- Vendor-native dashboards or visualizations. We consume data, not render UIs that match a vendor.
- Replacing vendor SDKs with our own clients. We use the SDKs they ship.
- Real-time push (webhooks/streaming from EDRs). Pull on demand.

## Decisions

### D1. One connector per category, registry resolution

Configuration declares one active connector per category. The registry resolves at engine boot:

```python
registry.resolve("edr")  # returns FalconConnector instance, or raises if not configured
registry.resolve("siem") # returns SplunkConnector
registry.resolve("identity") # returns OktaConnector
registry.resolve("email") # returns GraphMailConnector
```

The phishing playbook stops constructing connectors directly and goes through the registry. `--mock` registers the mock instances at higher precedence.

**Alternatives considered:** Pass connector instances explicitly into the playbook (rejected: every playbook signature grows; engine boot becomes the wrong place for credential resolution). Auto-detect from environment (rejected: too much magic; explicit config is clearer).

### D2. Shared base class, per-vendor module

```python
class BaseConnector(ABC):
    vendor_id: str
    category: str  # "edr" | "siem" | "identity" | "email"

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self._client = self._build_client()
        self._rate_limiter = RateLimiter(config.rate_limit)
        self._token_manager = OAuth2TokenManager(config) if config.uses_oauth else None

    @abstractmethod
    def _build_client(self) -> Any: ...

    def call(self, operation: str, *, dry_run: bool, **kwargs) -> Any:
        # logs audit row, applies rate limit, refreshes token if needed,
        # retries with backoff, re-raises on terminal failure
        ...
```

Per-vendor modules (e.g., `falcon.py`, `splunk.py`) extend the appropriate category-specific subclass (`EDRConnector`, `SIEMConnector`, etc.) and implement just the operation methods using their vendor SDK.

**Alternatives considered:** Each vendor connector entirely standalone (rejected: copy-paste of OAuth/retry/audit; drift across vendors). Heavy framework that abstracts vendor SDK (rejected: vendors evolve faster than abstraction; we'd be the bottleneck).

### D3. Configuration in same file as threat-platform-integration

`~/.vlair/integrations.json` already exists from threat-platform-integration. Add `connectors` section:

```json
{
  "connectors": {
    "edr": {"vendor": "crowdstrike", "client_id_env": "VLAIR_FALCON_ID", "client_secret_env": "VLAIR_FALCON_SECRET", "cloud": "us-1"},
    "siem": {"vendor": "splunk", "url": "https://splunk.example.com:8089", "token_env": "VLAIR_SPLUNK_TOKEN", "verify_ssl": true},
    "identity": {"vendor": "okta", "domain": "example.okta.com", "token_env": "VLAIR_OKTA_TOKEN"},
    "email": {"vendor": "microsoft_graph", "tenant_id": "...", "client_id_env": "VLAIR_GRAPH_ID", "client_secret_env": "VLAIR_GRAPH_SECRET"}
  }
}
```

**Alternatives considered:** Per-connector config files (rejected: more places to look). Database storage (rejected: the file is the source of truth in vlair).

### D4. Dry-run is connector-level, not engine-level

When `dry_run=True` is passed to a connector call, the connector logs the intended operation and parameters to audit and returns a deterministic stub response (sufficient for the playbook step to continue with synthetic data). This lets `vlair investigate --dry-run` exercise the full playbook without touching any production system.

**Alternatives considered:** Engine-level dry-run that short-circuits before connector calls (rejected: doesn't exercise the full playbook; less valuable for testing).

### D5. Failure isolation per step

Connector failures (timeout, 5xx after retries, auth failure) raise a typed `ConnectorError` that the engine catches at step boundaries. The step is recorded as `failed` with the error message, but the investigation continues to the next step rather than aborting. The verdict computation factors in step success rates.

**Alternatives considered:** Abort the whole investigation on connector failure (rejected: a SIEM outage shouldn't kill the email-only steps).

### D6. Connector status table

`connector_status(vendor_id, category, last_success_at, last_failure_at, last_error_message, configured_at)` — populated on every call. Surfaced via `vlair connectors status` and `GET /api/connectors`. This is operational visibility for operators ("is my Splunk connector working?") without spelunking through audit logs.

### D7. OAuth2 token refresh shared logic

`OAuth2TokenManager` handles client_credentials flow with token caching in memory and proactive refresh at 80% of token lifetime. Tokens are NEVER persisted to disk. On 401, the manager refreshes once and the call retries; second 401 propagates as auth failure.

### D8. Per-vendor rate limits documented and enforced

Each vendor module declares its rate limit (calls/minute) as a class constant. The shared `RateLimiter` enforces this with a token bucket. Hitting the limit triggers backoff, not a hard error.

| Vendor | Documented limit | Configured limit |
|--------|-----------------|------------------|
| CrowdStrike | 6000/min (varies by endpoint) | 100/min default |
| SentinelOne | 1000/min | 100/min default |
| Defender for Endpoint | 100/min for some endpoints | 60/min default |
| Splunk | depends on instance | 30/min default |
| Sentinel | 200/min | 60/min default |
| Elastic | depends on cluster | 60/min default |
| Okta | 600/min for orgs | 60/min default |
| Entra ID | varies | 60/min default |
| Microsoft Graph (Mail) | 10000/10min/app | 100/min default |
| Google Workspace | depends on quota | 60/min default |

Defaults are conservative; operators can raise via config.

### D9. Mocks register alongside real connectors

`--mock` doesn't replace the registry — it adds higher-precedence mock instances. This means mock and real can coexist (e.g., real SIEM, mock EDR for environments where the EDR isn't yet onboarded). Operators set `--mock=edr,identity` to selectively mock.

**Alternatives considered:** Binary --mock flag that mocks everything (rejected: too coarse; mixed environments are common during rollout).

## Risks / Trade-offs

- [Risk] Vendor SDK breaks between minor versions. → Mitigation: pin SDK versions in extras; CI runs against pinned versions; documented upgrade procedure.
- [Risk] Credential leakage via audit logs. → Mitigation: framework strips Authorization headers before logging; audit log unit test asserts no token-shaped strings appear.
- [Risk] Rate-limit blocking critical investigations. → Mitigation: rate limit applies per-connector, per-process; high-priority investigations can bypass via `--no-rate-limit` (admin only); 429 from vendor is respected regardless of local limit.
- [Risk] OAuth refresh storms during clock skew. → Mitigation: 80% lifetime threshold leaves room; clock skew detected and logged; manual refresh available via `vlair connectors test --refresh`.
- [Risk] Multi-tenant workspaces can't share connector configs. → Mitigation: this change scopes connector config per-workspace once multi-tenant lands (see multi-tenant-workspaces change); v1 ships single-tenant.
- [Trade-off] Nine connectors in one change is large. We could split per-category into four changes. We're betting the shared framework is the load-bearing piece and per-category split would just delay the framework's first stress test.
- [Risk] Real connector tests need API access; CI can't run them. → Mitigation: per-vendor mock fixtures using recorded responses (`vcrpy` or hand-rolled); manual integration test checklist documented; tagged tests skipped in CI by default.

## Migration Plan

1. Land `connector-framework` (base class, registry, OAuth/retry/rate-limit shared logic, status table, dry-run plumbing). All existing mock-based tests continue to pass.
2. Land first SIEM connector (Splunk — most-deployed). Wire phishing playbook to use registry; mock fallback when not configured.
3. Land first EDR connector (CrowdStrike — largest install base). Same pattern.
4. Land first Identity connector (Okta).
5. Land first Email connector (Microsoft Graph).
6. Land remaining vendors in sequence: SentinelOne, Defender, Sentinel, Elastic, Entra, Google Workspace. Each in its own PR following the established pattern.
7. Update `docs/INVESTIGATION.md` to drop "mock-only in production" caveat. Update `docs/CONNECTORS.md` with per-vendor setup recipes.

**Rollback:** Per-vendor rollback by removing credentials from config — connector becomes inactive; engine falls back to mock or records "unavailable". No schema migration to revert beyond the additive `connector_status` table.

## Open Questions

- Should connector retry policy be configurable per-call (e.g., short-timeout for liveness checks, long-timeout for SIEM searches)? (Recommendation: configurable per operation class, with sensible defaults.)
- Should we support connector profiles (e.g., "production Splunk" vs "staging Splunk")? (Recommendation: defer; one per category is enough for v1.)
- How do we handle vendor-specific data extensions (e.g., Falcon's per-detection metadata)? (Recommendation: the connector returns the standard DTO plus an `extensions: dict` blob; playbooks that care about a vendor's specifics can opt in.)
- Should `--no-rate-limit` exist at all? (Recommendation: yes, admin-only with audit log entry; emergencies happen.)
