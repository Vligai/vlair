## ADDED Requirements

### Requirement: Source platform attribution on stored IOCs

The `threat_feed_iocs` schema SHALL gain `source_platform` (string) and `platform_event_id` (string, nullable) columns. Every IOC inserted via a threat-platform connector SHALL populate these fields. IOCs gathered from non-platform sources (ThreatFox, URLhaus) SHALL set `source_platform` to the source name (`"threatfox"`, `"urlhaus"`).

#### Scenario: Migration of existing rows
- **WHEN** the schema migration runs on an existing vlair database
- **THEN** rows with feed source `"threatfox"` are backfilled with `source_platform="threatfox"`; URLhaus rows with `source_platform="urlhaus"`; rows with no recorded source receive `source_platform="legacy"`

#### Scenario: Filter by platform
- **WHEN** the analyst runs `vlair feeds list --source-platform misp`
- **THEN** only IOCs originating from MISP are returned

### Requirement: Merge semantics on cross-platform duplicates

When the same `(value, type)` IOC arrives from multiple platforms, the aggregator SHALL upsert with merge semantics: keep the highest confidence, union the source platforms, union the tag list, and preserve the earliest `first_seen` and latest `last_seen` timestamps.

#### Scenario: Same IOC from MISP and ThreatFox
- **WHEN** `evil.example.com` is pulled from ThreatFox at confidence 70 and from MISP at confidence 85
- **THEN** the stored row has confidence 85, `source_platforms=["threatfox","misp"]`, and the union of both source tags

### Requirement: Per-platform de-duplication key

De-duplication SHALL be keyed by `(source_platform, platform_event_id, value, type)` for platform-sourced IOCs, allowing the same IOC value to be tracked across distinct platform events without collapsing.

#### Scenario: Same IOC across MISP events
- **WHEN** `1.2.3.4` appears in MISP events 100 and 200, both pulled
- **THEN** two rows exist in the per-event provenance audit table, but a single canonical IOC row in `threat_feed_iocs` carrying both provenance references
