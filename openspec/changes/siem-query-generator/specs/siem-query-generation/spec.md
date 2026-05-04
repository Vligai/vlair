## ADDED Requirements

### Requirement: Generate query from investigation result

The system SHALL accept a vlair investigation result, a target dialect, and a time range, and SHALL return a structured response containing the query, an explanation, warnings, and the IOCs included.

#### Scenario: Splunk SPL generation
- **WHEN** the generator is invoked with an investigation result containing 3 IPs and 2 domains, dialect=`splunk`, time_range=`7d`
- **THEN** the response contains an SPL query referencing all 5 IOCs, an `explanation`, a `warnings` list, and `iocs_included` with the 5 IOC strings

#### Scenario: KQL generation
- **WHEN** dialect=`sentinel` is requested
- **THEN** the response uses Sentinel KQL syntax (`union`, `ago(7d)`) and references the IOCs in a KQL-idiomatic `in~` predicate

#### Scenario: Multi-dialect generation
- **WHEN** the generator is invoked with `dialects=["splunk","sentinel","elastic"]`
- **THEN** the response is a dict keyed by dialect with per-dialect query objects

### Requirement: Output validation

The system SHALL validate that the AI provider's response parses as JSON with all required fields. On parse failure SHALL retry once with a stricter prompt; on second failure SHALL return the dialect's templated fallback query and a warning.

#### Scenario: First parse fails, retry succeeds
- **WHEN** the AI returns malformed JSON on the first call but valid JSON on retry
- **THEN** the response uses the retry result and writes a `parse_retry` audit row

#### Scenario: Both parses fail
- **WHEN** both attempts fail
- **THEN** the response contains the templated fallback query, `warnings: ["AI generation failed; fallback query in use"]`, and `source: "fallback"`

### Requirement: Cache reuse

Repeated invocations with the same `(dialect, time_range, canonicalized IOC set)` SHALL return cached results without invoking the AI provider. Cache TTL SHALL match the existing AI-cache TTL (24h default).

#### Scenario: Cache hit
- **WHEN** the same investigation is re-queried within 24h with the same dialect and time range
- **THEN** the AI provider is not called and the response includes `cached: true`

#### Scenario: Cache miss on dialect change
- **WHEN** the same investigation is re-queried with a different dialect
- **THEN** the AI provider is called and the new result is cached separately

### Requirement: Privacy stripping

Inputs to the query generator SHALL be passed through the existing `ai/privacy.py` sanitizer before the prompt is constructed. RFC-1918 IPs, file contents, and any field flagged sensitive SHALL not appear in the prompt or in the cached entry.

#### Scenario: Internal IP stripped
- **WHEN** the investigation result contains `192.168.1.42` in the IOC list
- **THEN** the prompt sent to the provider does not contain `192.168.1.42` and the generated query does not reference it

### Requirement: Schema hints from user config

The system SHALL load `~/.vlair/siem_schemas.json` if present and SHALL include the per-dialect hints in the prompt context. With no hints SHALL use neutral placeholders.

#### Scenario: Splunk index hint
- **WHEN** the config sets `splunk.index = "corp"` and dialect=`splunk` is requested
- **THEN** the generated query starts with `index=corp` (instead of `index=<your_index>`)

### Requirement: Fallback templated query

The system SHALL provide a non-AI templated query for each supported dialect, used when the AI provider is unavailable, the user passes `--no-ai`, or AI generation fails twice.

#### Scenario: No-AI flag
- **WHEN** the user passes `--no-ai` to `vlair query`
- **THEN** no AI provider is invoked and the templated fallback is returned with `source: "fallback"`

#### Scenario: No API key configured
- **WHEN** no AI provider is configured (`ANTHROPIC_API_KEY` unset, `OPENAI_API_KEY` unset, no Ollama reachable)
- **THEN** the generator returns the templated fallback with a `warnings` entry explaining the situation

### Requirement: Time range parsing

The system SHALL accept `time_range` values in Splunk-style relative format (`24h`, `7d`, `30d`) and ISO-8601 absolute ranges (`2026-04-01/2026-05-01`). Dialect-specific time syntax SHALL be derived from this canonical input.

#### Scenario: Relative range
- **WHEN** `time_range="7d"` is passed for dialect=`splunk`
- **THEN** the generated SPL contains `earliest=-7d` (or the equivalent)

#### Scenario: Absolute range
- **WHEN** `time_range="2026-04-01/2026-05-01"` is passed for dialect=`sentinel`
- **THEN** the generated KQL uses `between(datetime(2026-04-01) .. datetime(2026-05-01))`
