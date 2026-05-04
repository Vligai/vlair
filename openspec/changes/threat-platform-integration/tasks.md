## 1. Dependencies and packaging

- [ ] 1.1 Add optional extras `[misp]`, `[thehive]`, `[stix]` to `pyproject.toml` with pinned ranges (`pymisp>=2.4,<3.0`, `thehive4py>=2.0,<3.0`, `stix2>=3.0,<4.0`)
- [ ] 1.2 Document install recipes in `docs/INTEGRATIONS.md` (per-extra)
- [ ] 1.3 CI matrix entry that installs each extra in isolation and runs that platform's tests

## 2. Connector base and configuration

- [ ] 2.1 Create `src/vlair/integrations/threat_platform/__init__.py` and `base.py` with `ThreatPlatformConnector` ABC
- [ ] 2.2 `models.py`: `NormalizedIOC`, `PlatformEvent`, `PlatformCase`, `PlatformReference`, `EnrichmentResult` dataclasses
- [ ] 2.3 `config.py`: load `~/.vlair/integrations.json`, env-var overrides, validation, friendly error on malformed file
- [ ] 2.4 Connector registry: discover concrete subclasses, gate on `is_configured()`
- [ ] 2.5 Tests: config loader (file only / env override / malformed); registry filtering by configured

## 3. Schema migrations

- [ ] 3.1 Migration: add `source_platform`, `platform_event_id` to `threat_feed_iocs`; backfill from existing source identifiers
- [ ] 3.2 Migration: create `integration_actions` table with idempotency columns
- [ ] 3.3 Migration: create per-event provenance audit table for cross-event de-dup tracking
- [ ] 3.4 Tests: migrations are idempotent; rollback notes documented

## 4. MISP pull (read-only, lowest risk)

- [ ] 4.1 `misp.py`: `MISPConnector.pull_iocs(since)` using PyMISP `search` with timestamp filter
- [ ] 4.2 Attribute → `NormalizedIOC` mapping (ip-src/dst, domain, url, md5, sha256, email-src)
- [ ] 4.3 Tag filtering from `pull.tags`
- [ ] 4.4 Confidence derivation from `to_ids` flag and tag set
- [ ] 4.5 Persist `since` watermark per-platform for incremental pulls
- [ ] 4.6 Tests: mocked PyMISP; tag filter; watermark advances; non-supported attribute types are ignored with a warning

## 5. STIX import (read-only, file-driven)

- [ ] 5.1 `stix_import.py`: parse via `stix2`, walk `indicator` objects
- [ ] 5.2 Pattern parser flattens multi-pattern objects to multiple `NormalizedIOC` rows
- [ ] 5.3 `valid_until` → `expires_at`; `confidence` → vlair confidence; `kill_chain_phases` → tags
- [ ] 5.4 Round-trip test against `common/stix_export.py` output
- [ ] 5.5 `--url` support with size and content-type guards

## 6. TheHive case creation

- [ ] 6.1 `thehive.py`: `TheHiveConnector.push_investigation` via thehive4py
- [ ] 6.2 Score-to-severity / TLP mapping helper with table-driven test
- [ ] 6.3 Case template instantiation; description with AI summary; observables from IOCs; tags from MITRE techniques
- [ ] 6.4 Idempotent re-push using `integration_actions`
- [ ] 6.5 Tests: case creation; re-push updates same case; severity mapping for boundary scores

## 7. MISP push (write, highest risk)

- [ ] 7.1 `MISPConnector.push_investigation` builds event with attributes from investigation IOCs
- [ ] 7.2 `push.enabled=false` default; `min_verdict_score` gate
- [ ] 7.3 Idempotency via `integration_actions` (skip / update / create branches)
- [ ] 7.4 Optional `push.include_summary` populates the event `comment` field
- [ ] 7.5 Tests: disabled-by-default; below-threshold rejected; re-push no-op; re-push update; concurrent push protection

## 8. TheHive enrichment webhook

- [ ] 8.1 `POST /api/integrations/thehive/enrich` endpoint in `webapp/app.py`
- [ ] 8.2 Bearer token auth scoped per-integration; rotation procedure documented
- [ ] 8.3 Lookup against `threat_feed_iocs` and recent investigations; assemble `EnrichmentResult`
- [ ] 8.4 Tests: 200 happy path; 401 missing/wrong token; unknown observable returns empty result not 404

## 9. Post-completion publishing hooks

- [ ] 9.1 Hook registry in `investigate/engine.py` invoked on `COMPLETED` transition
- [ ] 9.2 Register MISP push hook and TheHive open hook from `integrations/threat_platform`
- [ ] 9.3 `--no-auto-publish` flag plumbed through CLI, webapp, and engine
- [ ] 9.4 Result decorated with `published_to` references
- [ ] 9.5 Tests: hooks fire above threshold; hooks suppressed by flag; hook failure does not roll back investigation

## 10. CLI

- [ ] 10.1 `vlair misp pull` (with `--since`, `--tags`, `--dry-run`)
- [ ] 10.2 `vlair misp push <investigation_id>` (with `--dry-run`)
- [ ] 10.3 `vlair thehive open <investigation_id>` (with `--dry-run`)
- [ ] 10.4 `vlair stix import <bundle>` (file or `--url`)
- [ ] 10.5 Tests: each subcommand round-trips flags; exit codes; `--json` output schema

## 11. Webapp endpoints

- [ ] 11.1 `POST /api/integrations/misp/pull` (analyst)
- [ ] 11.2 `POST /api/integrations/misp/push` (senior_analyst)
- [ ] 11.3 `POST /api/integrations/thehive/open` (senior_analyst)
- [ ] 11.4 `POST /api/integrations/stix/import` (analyst)
- [ ] 11.5 SPA: investigation result page surfaces "Published to" links and "Push to MISP / Open in TheHive" buttons (gated)
- [ ] 11.6 Tests: role gating; audit rows on every action

## 12. Documentation

- [ ] 12.1 `docs/INTEGRATIONS.md`: configuration recipes for MISP, TheHive, STIX
- [ ] 12.2 Update `docs/DEPLOYMENT.md`: credential management, env-var reference
- [ ] 12.3 Update `docs/INDEX.md` quick-reference with new CLI commands
- [ ] 12.4 Migration / rollback procedure noted in `docs/ROADMAP.md`
