## ADDED Requirements

### Requirement: Investigation workspace scoping

Every investigation record SHALL include a `workspace_id`. Investigations SHALL be visible only to members of the workspace in which they were created.

#### Scenario: Investigation belongs to active workspace
- **WHEN** a user with `wsid=A` starts a phishing investigation
- **THEN** the new row in `investigations` has `workspace_id=A`

#### Scenario: List by workspace
- **WHEN** a user with `wsid=A` calls `vlair investigate list`
- **THEN** the response contains only investigations with `workspace_id=A`

### Requirement: Connectors receive workspace context

Investigation connectors (Email, SIEM, EDR, Identity) SHALL receive a `workspace_id` in their context object so that future per-workspace credentials and configuration can be wired in without API changes.

#### Scenario: Connector receives context
- **WHEN** the engine invokes a connector method
- **THEN** the call includes a `WorkspaceContext` containing the workspace UUID, slug, and a per-workspace settings dict (initially empty)

### Requirement: State store enforces tenant boundaries

The investigation SQLite state store SHALL apply the same scoped-query enforcement as the webapp: every read or write to `investigations`, `investigation_steps`, and `remediation_actions` includes the workspace filter.

#### Scenario: Cross-workspace read returns empty
- **WHEN** a query for investigation `INV-2026-05-03-XXXX` runs with the wrong workspace
- **THEN** the state store returns `None` and writes a `cross_workspace_lookup_attempt` audit row
