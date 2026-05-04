## ADDED Requirements

### Requirement: Post-completion publishing hooks

The investigation engine SHALL invoke registered post-completion hooks when an investigation transitions to `COMPLETED` with a verdict. The threat-platform integrations SHALL register hooks for MISP push and TheHive case creation. Hooks SHALL respect per-platform thresholds and `enabled` flags from `~/.vlair/integrations.json`.

#### Scenario: Auto-publish on completion
- **WHEN** an investigation completes with `verdict="Malicious"` and score 85, MISP `push.enabled=true` with `min_verdict_score=70`, and TheHive `open_on.enabled=true` with `min_verdict_score=70`
- **THEN** both hooks fire: a MISP event is created and a TheHive case is opened, both linked to the investigation via `integration_actions`

#### Scenario: Hook failure does not roll back the investigation
- **WHEN** the MISP push hook fails due to a network error after the investigation has already completed
- **THEN** the investigation remains `COMPLETED`, the failure is recorded in `integration_actions` with `status="error"`, and an audit row captures the failure; a retry is possible later

### Requirement: Per-investigation override of auto-publish

The investigation API and CLI SHALL accept an optional `--no-auto-publish` flag (and equivalent JSON field) that suppresses post-completion hooks for a single investigation, regardless of platform configuration.

#### Scenario: Sensitive case opt-out
- **WHEN** an analyst runs `vlair investigate phishing --file suspicious.eml --no-auto-publish`
- **THEN** the investigation completes normally but no MISP or TheHive write is performed

### Requirement: Investigation result links back to platform-side identifiers

When publishing hooks fire successfully, the investigation result SHALL gain `published_to` references containing each `{platform, kind, platform_event_id, url}` tuple, surfaced in CLI output, JSON results, and the SPA.

#### Scenario: SPA shows links
- **WHEN** the analyst opens an investigation result page in the SPA after a successful MISP+TheHive publish
- **THEN** the page shows two clickable links: "MISP event #42" and "TheHive case #~17", each linking to the platform-side resource
