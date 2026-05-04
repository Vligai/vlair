## ADDED Requirements

### Requirement: Playbooks use the connector registry

Existing and future playbooks SHALL resolve connectors via the registry rather than constructing them directly. The phishing playbook SHALL be migrated as part of this change.

#### Scenario: Phishing playbook with real connectors
- **WHEN** an analyst runs `vlair investigate phishing --file suspicious.eml` against an environment configured for Splunk + CrowdStrike + Okta + Microsoft Graph
- **THEN** the playbook executes against all four real systems; mock connectors are not invoked

#### Scenario: Phishing playbook in mixed mode
- **WHEN** the analyst runs `vlair investigate phishing --file suspicious.eml --mock=edr` against an environment configured for SIEM, Identity, and Email
- **THEN** the EDR connector is the mock; the other three are real

### Requirement: Failure isolation per step

Connector failures SHALL be caught at step boundaries. The affected step SHALL be recorded as `failed` with the connector error message, but the investigation SHALL continue to subsequent steps.

#### Scenario: SIEM outage doesn't kill the investigation
- **WHEN** the SIEM connector returns 503 after retries during a step that searches for URL clicks
- **THEN** the URL-click step records `status="failed"` with the error; the investigation continues to subsequent steps; the final verdict notes the degraded data quality

### Requirement: Verdict factors in step success rate

The verdict computation SHALL factor in the proportion of steps that completed successfully. When a critical step (configured per playbook) fails, the verdict SHALL include a `degraded_data_quality: true` flag and the confidence component of the score SHALL be reduced.

#### Scenario: Degraded confidence on critical-step failure
- **WHEN** the URL-clicks step (marked critical for phishing) fails due to SIEM outage
- **THEN** the investigation result has `degraded_data_quality=true`; the verdict score is unchanged but the confidence component is reduced; the SPA renders a warning banner explaining which step failed

### Requirement: Real-connector remediation gated by role

Remediation actions (host isolation, account disable, message purge) executed via real connectors SHALL require the `senior_analyst` role. When invoked by a lower-role user, the step SHALL record `failed: insufficient_role` and the audit log SHALL record the denial.

#### Scenario: Mock allows remediation regardless of role
- **WHEN** an `analyst`-role user runs `vlair investigate phishing --mock` and the playbook reaches a remediation step
- **THEN** the mock connector executes the synthetic remediation; the role gate applies only to real connectors

### Requirement: Per-investigation connector overrides

The investigation API and CLI SHALL accept optional per-category connector vendor overrides (e.g., `--siem-vendor sentinel`) for investigations that need to query a different vendor than the one configured globally. Overrides SHALL only apply when credentials for the override vendor are present.

#### Scenario: Override to alternate SIEM
- **WHEN** an analyst runs `vlair investigate phishing --file x.eml --siem-vendor sentinel` and Sentinel credentials are configured alongside the default Splunk
- **THEN** the investigation's SIEM steps use Sentinel; other categories continue using their configured vendors

#### Scenario: Override without credentials
- **WHEN** the analyst attempts `--siem-vendor sentinel` but Sentinel is not configured
- **THEN** the command fails with `ConnectorNotConfiguredError` before any step runs
