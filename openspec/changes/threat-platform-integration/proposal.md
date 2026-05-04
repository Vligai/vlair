## Why

vlair generates IOCs and verdicts but lives in isolation from the threat-platforms most SOCs already operate. Two integrations would close that gap: MISP (the open standard for threat-intel sharing) and TheHive (the open case-management system). vlair already exports STIX 2.1 — the round-trip is missing because it can't *import*. Adding all three under a unified "threat platform" connector layer is cheaper than three separate efforts because they share patterns: HTTPS API client, paginated pull, idempotent push, role-gated.

## What Changes

- New `integrations/threat_platform/` package with one connector class per platform: `MISPConnector`, `TheHiveConnector`, `STIXImporter`. Common base in `integrations/threat_platform/base.py`.
- **MISP — pull**: scheduled / on-demand pull of MISP events tagged with configured tags into the vlair `threat_feed_iocs` store. Confidence scoring updates based on MISP's `to_ids` flag and tag set. Source attribution preserved.
- **MISP — push**: when a vlair investigation reaches `Malicious` verdict above a configurable threshold, optionally publish a new MISP event with all enriched IOCs as attributes. Idempotent (re-push updates the existing event).
- **TheHive — case creation**: when an investigation completes with verdict above threshold, optionally open a TheHive case with: IOCs as observables, AI summary in the description, MITRE ATT&CK techniques as tags, severity/TLP from the vlair scorer, and a back-link to the vlair investigation result.
- **TheHive — observable enrichment**: a webhook endpoint TheHive calls during analyzer execution, returning vlair's enrichment for a single observable.
- **STIX import**: `vlair stix import <file.json|http://...>` parses STIX 2.1 bundles and inserts indicators into `threat_feed_iocs`. Round-trips with the existing exporter.
- New CLI commands: `vlair misp pull`, `vlair misp push <investigation_id>`, `vlair thehive open <investigation_id>`, `vlair stix import <bundle>`.
- New webapp endpoints for each operation, role-gated to `senior_analyst` (modifying actions) or `analyst` (read-only pulls).
- Configuration: per-platform credentials in env vars or `~/.vlair/integrations.json`. Tag/confidence/severity mappings live in the same file.
- Audit log captures every cross-platform action with platform-specific identifiers (MISP event ID, TheHive case ID).

## Capabilities

### New Capabilities
- `threat-platform-integration`: MISP, TheHive, and STIX-import connectors with shared configuration, audit, and role-gating patterns.

### Modified Capabilities
- `threat-feed-aggregator`: existing aggregator gains `source_platform` attribution and de-duplication keyed by `(platform, platform_event_id, ioc)`.
- `investigation-automation`: investigations gain optional auto-publish hooks (MISP event, TheHive case) at completion.

## Non-goals

- Bidirectional real-time sync (push-on-write to MISP, pull-on-read from TheHive). v1 is request/response and scheduled batch.
- TheHive 4 support (we target TheHive 5 only — different API). Documented as a constraint.
- MISP galaxy / object support beyond standard attributes. v1 handles `ip-src`, `ip-dst`, `domain`, `url`, `md5`, `sha256`, `email-src`. Galaxy support is a follow-up.
- Cortex analyzer registration (writing vlair as a Cortex analyzer). Out of scope; the webhook-from-TheHive pattern in this change is sufficient for the same use case.
- Automated case closure / status sync from TheHive back to vlair. The vlair investigation is the source of truth for analysis; TheHive owns case lifecycle.
- ATT&CK Workbench, OpenCTI. Tracked as future capabilities.

## Impact

- **Code**: new `integrations/threat_platform/` package; modifications to `tools/threat_feed_aggregator.py`, `investigate/engine.py` (post-completion hooks), `cli/main.py`, `webapp/app.py`, `common/stix_export.py` (sibling import module).
- **Schema**: `threat_feed_iocs` gains `source_platform` and `platform_event_id` columns; new `integration_actions` table records every platform-side write with idempotency keys.
- **Dependencies**: `pymisp>=2.4` (optional `[misp]` extra), `thehive4py>=2.0` (optional `[thehive]` extra), `stix2>=3.0` (optional `[stix]` extra; new — currently we only export, never import).
- **Tests**: per-platform mocked-API test files; integration test fixture using PyMISP's mock mode.
- **Docs**: new `docs/INTEGRATIONS.md` covering MISP, TheHive, STIX configuration recipes; updates to `docs/DEPLOYMENT.md` for credential management.
