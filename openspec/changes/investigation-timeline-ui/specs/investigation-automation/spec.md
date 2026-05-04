## ADDED Requirements

### Requirement: Step model gains timing and dependency fields

The `InvestigationStep` model SHALL include `started_at`, `completed_at`, `duration_ms`, `triggered_by`, and `depends_on` fields. The schema migration SHALL add these columns to the `investigation_steps` table.

#### Scenario: Migration backfill
- **WHEN** the migration runs against an existing database with steps lacking timing fields
- **THEN** existing rows have `started_at = created_at`, `completed_at = NULL` for in-progress and `created_at` for terminal-state steps as a best-effort backfill, `duration_ms = NULL`, `triggered_by = "automatic"`, `depends_on = []`

### Requirement: Engine populates timing fields

The investigation engine SHALL record `started_at = now()` immediately before invoking a step's run logic, and `completed_at = now()` and `duration_ms = (completed_at - started_at)` immediately after. For steps that paused for approval, the engine SHALL record `started_at` from the original attempt and accumulate `duration_ms` only across active execution windows (excluding pause time).

#### Scenario: Active execution time only
- **WHEN** a step pauses for 2 hours waiting on approval and the post-approval execution takes 4 seconds
- **THEN** `duration_ms = 4000` (the pause time is excluded from active duration)

### Requirement: Playbooks declare dependencies

The `BasePlaybook` ABC SHALL accept `depends_on: list[str]` per step. Existing playbooks (phishing, malware-triage, ioc-hunt, network-forensics, log-investigation) SHALL be updated to declare explicit dependencies. New playbooks SHALL declare dependencies as part of their step definitions.

#### Scenario: Phishing playbook dependencies
- **WHEN** the phishing playbook is loaded
- **THEN** `extract_iocs` declares `depends_on=["parse_email"]`; `lookup_hashes` declares `depends_on=["extract_iocs"]`; `find_recipients` declares `depends_on=["parse_email"]` (parallel-eligible with hash lookup)

### Requirement: Connector call attribution to steps

The connector framework's audit logging SHALL record `step_id` (when called from within a step) so the timeline endpoint can attribute calls to their parent step. Calls made outside the step lifecycle (e.g., manual `vlair connectors test`) SHALL have `step_id = NULL`.

#### Scenario: Step-attributed calls visible in timeline
- **WHEN** a phishing playbook's `lookup_hashes` step makes a VirusTotal call
- **THEN** the call's audit row has `step_id` populated; the timeline endpoint includes the call in `connector_calls` under that step
