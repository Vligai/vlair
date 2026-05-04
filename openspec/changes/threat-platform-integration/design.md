## Context

vlair's `tools/threat_feed_aggregator.py` already stores IOCs from ThreatFox and URLhaus in a normalized SQLite schema, with confidence scoring and de-duplication by IOC hash. `common/stix_export.py` produces STIX 2.1 bundles from vlair output. `investigate/connectors/` defines an abstract connector pattern with mock implementations. None of these systems talk to threat-platforms today.

The natural shape: a new `integrations/threat_platform/` package paralleling the existing `integrations/` for chat platforms, with one connector class per system and shared configuration loading. PyMISP and thehive4py are mature, well-documented, and stable — we don't need to roll our own clients. The `stix2` library handles import the same way.

The question is how cleanly we can mash three different platforms into one shared layer. They share more than they differ: HTTPS+token auth, paginated pull, idempotent write keyed by an external identifier, configurable mapping between vlair concepts and platform concepts. A small base class with `pull()`, `push(investigation)`, `enrich(observable)` covers it, and per-platform overrides handle the specifics.

## Goals / Non-Goals

**Goals:**
- One vlair instance can pull MISP feeds, publish MISP events on `Malicious` verdicts, open TheHive cases automatically, and import STIX bundles — all configured from one file.
- Idempotent writes: re-running a push updates the existing event/case rather than creating a duplicate.
- Source attribution preserved: every IOC pulled from MISP retains its origin event ID, source organization, and confidence rationale.
- Mock-based integration tests cover the full code path without requiring live MISP/TheHive instances.
- Shared configuration / credential layer so adding a fourth platform later is a small effort.

**Non-Goals:**
- Real-time event streaming.
- TheHive 4, MISP < 2.4 (deprecated upstream).
- OpenCTI, EclecticIQ, Anomali — different shape, different change.
- IOC enrichment loops (vlair pulls from MISP, enriches, pushes back, MISP pulls vlair, enriches…). Detection of cycles is a future concern.
- Replacing `tools/threat_feed_aggregator.py`. The aggregator is the storage layer; this change adds source platforms.

## Decisions

### D1. Three connectors, one package, shared base

```
integrations/threat_platform/
  __init__.py
  base.py           # ThreatPlatformConnector ABC
  config.py         # loads ~/.vlair/integrations.json or env vars
  misp.py           # MISPConnector(ThreatPlatformConnector)
  thehive.py        # TheHiveConnector(ThreatPlatformConnector)
  stix_import.py    # STIXImporter (lighter — file-driven, no live API)
  models.py         # cross-platform DTOs: PlatformEvent, PlatformCase, etc.
```

Base interface:

```python
class ThreatPlatformConnector(ABC):
    name: str

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def pull_iocs(self, since: datetime) -> list[NormalizedIOC]: ...

    @abstractmethod
    def push_investigation(self, investigation: Investigation) -> PlatformReference: ...

    @abstractmethod
    def enrich_observable(self, observable: str, kind: str) -> Optional[EnrichmentResult]: ...
```

`STIXImporter` only implements `pull_iocs(file_path)` and is constructed differently — it's not a live API client.

**Alternatives considered:** One module per integration without a common base (rejected: makes adding the next platform a copy-paste exercise; common patterns drift). Inheritance from a single `Connector` shared with the investigation-engine connectors (rejected: different concerns — investigation connectors look up specific entities, threat-platform connectors batch sync IOCs).

### D2. Configuration in `~/.vlair/integrations.json`

Single JSON file with per-platform sections. Env vars override file values for credentials (so secrets stay out of the file in production). Schema:

```json
{
  "misp": {
    "url": "https://misp.example.com",
    "api_key_env": "VLAIR_MISP_KEY",
    "verify_ssl": true,
    "pull": {"tags": ["tlp:white", "vlair-trusted"], "since_days": 7},
    "push": {"enabled": false, "min_verdict_score": 70, "info_template": "vlair: {summary}", "default_tags": ["vlair-source"]}
  },
  "thehive": {
    "url": "https://thehive.example.com",
    "api_key_env": "VLAIR_THEHIVE_KEY",
    "case_template": "phishing-template",
    "open_on": {"enabled": true, "min_verdict_score": 70}
  },
  "stix": {
    "default_tlp": "amber"
  }
}
```

**Alternatives considered:** Per-platform env vars only (rejected: too many vars, hard to document mappings). YAML (rejected: vlair already standardizes on JSON for runtime config; adding YAML is gratuitous).

### D3. Idempotent push via external-ID-keyed table

New table `integration_actions(platform, kind, vlair_investigation_id, platform_event_id, last_pushed_at, payload_hash)`. Before pushing:
1. Look up `(platform, "push", investigation_id)`. If found and `payload_hash` matches the new payload, skip.
2. If found with different `payload_hash`, update the existing platform event/case and refresh `last_pushed_at`.
3. If not found, create a new platform event/case and insert the row.

This makes "rerun the push" safe and resolves the most common analyst question ("did this already get sent to MISP?").

### D4. Pull is incremental and source-attributed

`MISPConnector.pull_iocs(since)` queries `events.timestamp > since`, walks attributes, and emits `NormalizedIOC` objects with:

```python
NormalizedIOC(
    value="evil.example.com",
    type="domain",
    confidence=85,
    source_platform="misp",
    source_event_id="42",
    source_organization="Acme CIRT",
    tags=["tlp:white", "actor:apt28"],
    seen_at=datetime,
)
```

Storage in `threat_feed_iocs` is upsert on `(value, type)` with merge semantics: keep the highest confidence, union source platforms and tags. The user can later filter by platform.

**Alternatives considered:** Separate table per platform (rejected: query layer becomes a UNION mess). Storing raw MISP attribute as JSON blob (rejected: defeats normalization).

### D5. TheHive case creation via case template

TheHive 5 supports case templates (server-side). vlair references a template by name; the connector instantiates the case from the template, fills in the description with the AI summary, attaches IOCs as observables, and adds MITRE techniques as tags. TLP and severity flow from the vlair scorer:

| Vlair score | TLP   | TheHive severity |
|-------------|-------|------------------|
| 0–39        | green | low              |
| 40–69       | amber | medium           |
| 70–89       | amber | high             |
| 90–100      | red   | critical         |

**Alternatives considered:** Build the case from scratch without a template (rejected: customers customize templates heavily; this honors their work). Sync custom field values back from TheHive (rejected: lifecycle ownership concern, deferred).

### D6. TheHive enrichment webhook

A webhook endpoint `POST /api/integrations/thehive/enrich` that TheHive's analyzer framework can call mid-analysis. Body: `{observable: "evil.com", type: "domain"}`. Response: vlair's intel (verdict, score, sources, last seen). Authentication via a shared bearer token configured per integration.

This sidesteps writing a Cortex analyzer (which is heavier) while still enabling the "TheHive sees an IOC, asks vlair, receives enrichment" pattern.

### D7. STIX import is file-driven and read-only

`vlair stix import file.json` (or `--url`) parses the bundle with `stix2`, walks `indicator` objects, normalizes to `NormalizedIOC`, and upserts into `threat_feed_iocs`. STIX `valid_until` becomes `expires_at`. STIX `confidence` (when present) becomes vlair confidence. STIX `kill_chain_phases` flow into the IOC's tag list.

**Alternatives considered:** Live TAXII pulling (deferred to a future capability — separate change).

### D8. Audit and traceability

Every connector action writes an audit row: `action="misp.push" detail="event_id=42 score=85 investigation=INV-..."`. The webapp's audit log query already shows these. The new `integration_actions` table is the operational record (idempotency); audit_log is the security record (who did what when).

## Risks / Trade-offs

- [Risk] Pushing wrong IOCs to MISP pollutes a shared community feed. → Mitigation: `push.enabled` defaults to `false`; analyst review step in the SPA before publish; `min_verdict_score` gate; default tags clearly identify vlair as the source.
- [Risk] TheHive case spam if the threshold is too low. → Mitigation: `min_verdict_score=70` default; per-investigation override flag; rate limit on auto-creation (max 50 cases/hour per workspace).
- [Risk] STIX import accepts malicious indicators that taint the local feed. → Mitigation: imported IOCs are tagged `imported:stix:<filename>` and start at confidence 50 (medium); analyst review queue before promotion to high-confidence status.
- [Risk] PyMISP/thehive4py dependency conflicts with existing deps. → Mitigation: `[misp]`, `[thehive]`, `[stix]` are optional extras; only enabled deployments install them.
- [Risk] TheHive 5 API changes between minors. → Mitigation: pin to `thehive4py>=2.0,<3.0`; CI runs against the pinned version; documented upgrade procedure.
- [Trade-off] Supporting three platforms in one change is a big PR; alternative would be three separate changes. We're betting the shared pattern is worth landing together.

## Migration Plan

1. Land the connector base class, configuration loader, and `integration_actions` table — no platform-specific code yet. Safe, additive.
2. Land MISP pull (lowest risk: read-only). Test against a staging MISP instance.
3. Land STIX import (also read-only, file-driven). Test round-trip with the existing exporter.
4. Land TheHive case creation (write, but to a single platform per investigation). Beta with `case_template` configured.
5. Land MISP push (multi-target write — riskiest). Default disabled; opt-in beta.
6. Land TheHive enrichment webhook.
7. Document everything in `docs/INTEGRATIONS.md`; deprecate the mock SIEM connector docs in favor of pointing at this change.

**Rollback:** Per-platform rollback by removing the credentials from config — connector becomes inactive. No schema migration to revert beyond the additive `integration_actions` table.

## Open Questions

- Should MISP push include vlair's AI summary in the event `comment` field, or only IOCs? (Recommendation: opt-in via `push.include_summary` — some orgs want minimal sharing.)
- TheHive: case-per-investigation or alert-per-investigation? (Recommendation: case for `Malicious` ≥ 70, alert for `Suspicious` 40–69. Configurable.)
- Should the connector framework re-export to the investigation-engine connector contracts? (Recommendation: no — different lifecycle and concerns; keep separate.)
- STIX import: how to handle indicators with multiple `pattern` types in one object? (Recommendation: flatten to multiple `NormalizedIOC` rows with same `source_event_id`.)
