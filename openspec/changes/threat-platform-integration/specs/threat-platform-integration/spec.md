## ADDED Requirements

### Requirement: Threat platform connector base interface

The system SHALL provide an abstract `ThreatPlatformConnector` base class with `is_configured()`, `pull_iocs(since)`, `push_investigation(investigation)`, and `enrich_observable(observable, kind)` methods. Concrete connectors SHALL implement this interface.

#### Scenario: Adding a new platform
- **WHEN** a developer adds a fourth threat platform
- **THEN** they subclass `ThreatPlatformConnector`, implement the four abstract methods, and the platform is automatically discoverable via the connector registry without changes to the engine, CLI dispatcher, or webapp endpoints

### Requirement: Per-platform configuration with env override

Configuration SHALL be loaded from `~/.vlair/integrations.json` with per-platform sections. Credential fields (`api_key`) SHALL be referenced by env var name (`api_key_env: "VLAIR_MISP_KEY"`) rather than stored in the file. Env var values SHALL override file values when both are present.

#### Scenario: Env var overrides file
- **WHEN** `~/.vlair/integrations.json` defines `misp.url` and `VLAIR_MISP_URL` is also set
- **THEN** the connector uses the env var value, and the audit log notes the override source

#### Scenario: Missing credential disables platform
- **WHEN** a platform section exists in the config but its `api_key_env` var is not set
- **THEN** `is_configured()` returns False and the connector is not registered for use; CLI and webapp surface a clear "not configured" message

### Requirement: MISP pull is incremental and source-attributed

`MISPConnector.pull_iocs(since)` SHALL query MISP for events with `timestamp > since`, walk attributes, and emit `NormalizedIOC` objects carrying `source_platform="misp"`, `source_event_id`, `source_organization`, `tags`, `confidence`, and `seen_at`.

#### Scenario: Incremental pull
- **WHEN** the analyst runs `vlair misp pull` after a previous successful pull at T1
- **THEN** only MISP events with `timestamp > T1` are fetched and inserted/updated; unchanged events are skipped without a network round-trip per attribute

#### Scenario: Tag filter applied
- **WHEN** the configuration sets `pull.tags = ["tlp:white", "vlair-trusted"]`
- **THEN** only events carrying at least one matching tag are pulled

### Requirement: MISP push is idempotent

`MISPConnector.push_investigation(investigation)` SHALL look up `(platform="misp", kind="push", investigation_id)` in the `integration_actions` table. If a row exists with a matching payload hash, the call SHALL be a no-op. If the row exists with a different hash, the existing MISP event SHALL be updated rather than recreated. If no row exists, a new MISP event SHALL be created and a row inserted.

#### Scenario: Re-push with no changes
- **WHEN** an investigation is pushed to MISP and then pushed again with no intervening changes
- **THEN** no MISP API write call is made beyond the idempotency lookup; the response indicates `action="skipped"` and returns the existing MISP event ID

#### Scenario: Re-push after IOC added
- **WHEN** an investigation gains a new IOC and is pushed again
- **THEN** the existing MISP event is updated (not duplicated), `last_pushed_at` is refreshed, and the audit log records `action="misp.push.update"`

### Requirement: MISP push gated by verdict and disabled by default

The system SHALL only push investigations to MISP when `push.enabled=true` in configuration AND the investigation's vlair score is at or above `push.min_verdict_score` (default 70). Push SHALL be disabled by default in fresh installations.

#### Scenario: Default safety
- **WHEN** the operator installs vlair and configures MISP credentials without explicitly enabling push
- **THEN** `vlair misp push <id>` returns an error explaining push is disabled and how to enable it; no API write is attempted

#### Scenario: Score below threshold
- **WHEN** an investigation with score 55 is submitted to push and `min_verdict_score=70`
- **THEN** the push is rejected with a clear "score below threshold" message

### Requirement: TheHive case creation from template

`TheHiveConnector.push_investigation(investigation)` SHALL instantiate a TheHive 5 case from the configured `case_template`, fill in the description with the AI summary (when present), attach IOCs as observables, attach MITRE ATT&CK techniques as tags, and set TLP and severity from a deterministic mapping of the vlair score.

#### Scenario: Score-to-severity mapping
- **WHEN** investigations of scores 30, 50, 75, and 95 are pushed to TheHive
- **THEN** the resulting cases have severity `low/medium/high/critical` and TLP `green/amber/amber/red` respectively, matching the documented mapping table

#### Scenario: Idempotent case creation
- **WHEN** an investigation is opened in TheHive, then push is run again
- **THEN** the existing case is looked up via `integration_actions` and updated rather than duplicated

### Requirement: TheHive enrichment webhook

The webapp SHALL expose `POST /api/integrations/thehive/enrich` accepting `{observable, type}` and returning vlair's intelligence (verdict, score, sources, last seen) for that observable. The endpoint SHALL authenticate via a shared bearer token configured per integration in `integrations.json`.

#### Scenario: Successful enrichment
- **WHEN** TheHive's analyzer framework posts `{"observable": "evil.com", "type": "domain"}` with the configured bearer token
- **THEN** the response is 200 with vlair's structured intel for that domain, drawn from `threat_feed_iocs` and recent investigations

#### Scenario: Missing or wrong bearer token
- **WHEN** the request lacks the bearer token or sends a wrong one
- **THEN** the response is 401 and the audit log records `action="thehive.enrich.unauthorized"`

### Requirement: STIX 2.1 import from file or URL

The CLI SHALL expose `vlair stix import <file|--url URL>` that parses STIX 2.1 bundles, walks `indicator` objects, normalizes each pattern to a `NormalizedIOC`, and upserts into `threat_feed_iocs`. STIX `valid_until` SHALL map to `expires_at`. STIX `confidence` (when present) SHALL map to vlair confidence. STIX `kill_chain_phases` SHALL flow into the IOC's tag list.

#### Scenario: Round-trip with vlair STIX export
- **WHEN** vlair exports a bundle via `common/stix_export.py` and then imports the same bundle on another instance
- **THEN** the receiving instance has the same set of IOCs with the same confidence, expiry, and tags

#### Scenario: Multiple-pattern indicator
- **WHEN** a single STIX `indicator` object carries multiple `pattern` types (e.g., domain AND IP in one object)
- **THEN** multiple `NormalizedIOC` rows are inserted, all sharing the same `source_event_id` for traceability

### Requirement: Integration actions table for idempotency and audit

The system SHALL maintain an `integration_actions` table with columns `(id, platform, kind, vlair_investigation_id, platform_event_id, last_pushed_at, payload_hash, status, error_message)`. Every push attempt SHALL write or update a row. Connectors SHALL consult this table for idempotency checks.

#### Scenario: Failed push leaves a recoverable record
- **WHEN** a push fails mid-way (e.g., network error after platform write)
- **THEN** the row is written with `status="error"` and the error message; the next push attempt detects the partial state and reconciles rather than creating a duplicate

### Requirement: New CLI subcommands

The CLI SHALL expose `vlair misp pull`, `vlair misp push <investigation_id>`, `vlair thehive open <investigation_id>`, and `vlair stix import <bundle>`. Each SHALL respect `--dry-run`, `--verbose`, and `--json` flags consistent with the rest of vlair.

#### Scenario: Dry run shows what would happen
- **WHEN** the user runs `vlair misp push INV-... --dry-run`
- **THEN** stdout shows the MISP event payload that would be sent, the idempotency lookup result, and the configured threshold check, but no API write is performed

### Requirement: Webapp endpoints for each platform action

The webapp SHALL expose `POST /api/integrations/misp/pull`, `POST /api/integrations/misp/push`, `POST /api/integrations/thehive/open`, and `POST /api/integrations/stix/import`. Modifying actions (push, open) SHALL require the `senior_analyst` role. Read-only actions (pull, import) SHALL require at least the `analyst` role.

#### Scenario: Role gating enforced
- **WHEN** a user with the `analyst` role calls `POST /api/integrations/misp/push`
- **THEN** the response is 403 and the audit log records the denied attempt

### Requirement: Audit logging of all platform actions

Every connector action (pull, push, open, enrich, import) SHALL write a row to the existing `audit_log` table with `action` formatted as `<platform>.<verb>` (e.g., `misp.push`, `thehive.open`) and `detail` carrying the platform-side identifier and outcome.

#### Scenario: Audit row for successful push
- **WHEN** an analyst pushes an investigation to MISP successfully
- **THEN** an audit row is written with `action="misp.push"`, `detail` containing `event_id=<n> investigation=<id> score=<s>`, and the requesting user's identity

### Requirement: Optional dependency extras

PyMISP, thehive4py, and stix2 SHALL be declared as optional `pip` extras (`[misp]`, `[thehive]`, `[stix]`). The connector for an absent dependency SHALL fail `is_configured()` with a clear "dependency not installed" message rather than crashing on import.

#### Scenario: Module not installed
- **WHEN** vlair is installed without the `[misp]` extra and `vlair misp pull` is invoked
- **THEN** the user sees `MISP support is not installed; run pip install vlair[misp]` and exit code 1, not a Python ImportError trace
