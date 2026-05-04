## ADDED Requirements

### Requirement: Connector base class and registry

The system SHALL provide a `BaseConnector` ABC with `vendor_id`, `category`, and `call(operation, *, dry_run, **kwargs)` plumbing. A registry SHALL resolve one active connector per category at engine boot from `~/.vlair/integrations.json`. Playbooks SHALL access connectors via the registry rather than constructing them directly.

#### Scenario: Registry resolves configured connector
- **WHEN** the integrations file declares `connectors.siem.vendor="splunk"` and the Splunk credentials env vars are set
- **THEN** `registry.resolve("siem")` returns a configured `SplunkConnector` instance

#### Scenario: Unconfigured category returns absent
- **WHEN** no `edr` section is configured
- **THEN** `registry.resolve("edr")` raises `ConnectorNotConfiguredError` with a message naming the missing config keys

### Requirement: Mock connectors register at higher precedence

When the engine is invoked with `--mock=<categories>`, mock connectors for the listed categories SHALL register at higher precedence than configured real connectors, returning deterministic test data without making network calls.

#### Scenario: Selective mocking
- **WHEN** the operator runs `vlair investigate phishing --file x.eml --mock=edr`
- **THEN** the EDR connector is the mock, but SIEM/Identity/Email connectors remain the real configured ones

### Requirement: OAuth2 token refresh

For connectors using OAuth2 client_credentials, the framework SHALL cache tokens in memory, refresh proactively at 80% of token lifetime, and on a 401 SHALL refresh once and retry the call. Tokens SHALL NEVER be written to disk.

#### Scenario: Proactive refresh
- **WHEN** a token has 19% of its lifetime remaining
- **THEN** the next call refreshes the token before invoking the operation

#### Scenario: 401 triggers single refresh-and-retry
- **WHEN** the vendor returns 401 once
- **THEN** the framework refreshes the token and retries; if the retry also returns 401, an `AuthenticationError` is raised

### Requirement: Retry with exponential backoff

The framework SHALL retry transient failures (timeout, 5xx, 429) up to 3 times with exponential backoff (1s, 2s, 4s) plus jitter. Vendor-specified `Retry-After` headers SHALL override the local backoff calculation.

#### Scenario: Vendor 429 with Retry-After
- **WHEN** the vendor returns 429 with `Retry-After: 30`
- **THEN** the framework waits 30 seconds before retrying, regardless of the standard backoff schedule

### Requirement: Per-vendor rate limiting

Each connector SHALL declare a default rate limit (calls/minute). The framework SHALL enforce this with a token bucket. When the local limit would be exceeded, the framework SHALL block briefly to spread calls rather than dropping or erroring.

#### Scenario: Burst spreading
- **WHEN** a playbook makes 100 EDR calls in 1 second and the limit is 60/min
- **THEN** calls 1-60 proceed quickly, calls 61-100 are spread across the next minute, and no calls fail with rate-limit errors

#### Scenario: Operator override
- **WHEN** the integrations config sets `siem.rate_limit_per_minute: 120`
- **THEN** the configured value overrides the connector's default

### Requirement: Audit logging on every connector call

Every `BaseConnector.call(...)` invocation SHALL write an audit row containing `vendor`, `category`, `operation`, target identifier (when applicable), latency in ms, outcome (`success` / `error` / `rate_limited` / `dry_run`), and the requesting principal. Authorization headers and credentials SHALL be redacted from any captured request/response payload.

#### Scenario: Successful call audited
- **WHEN** an analyst runs a SIEM search via the playbook and Splunk returns results
- **THEN** an audit row is written with `vendor="splunk"`, `category="siem"`, `operation="search"`, the latency, and `outcome="success"`

#### Scenario: Credentials never logged
- **WHEN** any connector call is audited
- **THEN** no token-shaped string (`Bearer <hex>`, JWT) appears anywhere in the audit row's payload field; a unit test asserts this invariant against a fixture call

### Requirement: Dry-run returns synthetic responses

When called with `dry_run=True`, a connector SHALL log the intended operation to audit (with `outcome="dry_run"`) and return a deterministic synthetic response of the correct DTO shape, without making any network call.

#### Scenario: Dry-run host isolation
- **WHEN** `vlair investigate phishing --dry-run` reaches a step that would isolate a host
- **THEN** the EDR connector logs the intended isolation, returns a `HostIsolationResult` stub indicating the action would be taken, and makes no API call

### Requirement: Connector status table

A `connector_status(vendor_id, category, last_success_at, last_failure_at, last_error_message, configured_at)` table SHALL be maintained. Every call SHALL update either `last_success_at` or `last_failure_at`. The table SHALL be queryable via `vlair connectors status` and `GET /api/connectors`.

#### Scenario: Status reflects last call
- **WHEN** a SIEM call fails with timeout, then a subsequent call succeeds
- **THEN** the row shows both `last_failure_at` (older) and `last_success_at` (newer); operators see "currently healthy" inferred from the timestamps

### Requirement: Connector test command

The CLI SHALL expose `vlair connectors test <category|all>` that performs a lightweight health-check call against each configured connector (e.g., a no-op API call or `whoami`-equivalent), reports success/failure, and updates `connector_status`. The webapp SHALL expose the equivalent `POST /api/connectors/{category}/test`.

#### Scenario: All connectors healthy
- **WHEN** an admin runs `vlair connectors test all` with all four categories configured
- **THEN** the output lists each vendor with response latency and `OK`; exit code is 0

#### Scenario: One connector misconfigured
- **WHEN** the Splunk token is invalid
- **THEN** `vlair connectors test siem` reports `FAIL: 401 invalid_token` with the masked token prefix; exit code is non-zero
