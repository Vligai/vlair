## ADDED Requirements

### Requirement: log-investigation workflow runs Sigma by default

The `vlair workflow log-investigation` workflow SHALL include a Sigma-evaluation step that uses the bundled rule pack, in addition to the existing pattern-based detection.

#### Scenario: Default workflow run
- **WHEN** the user runs `vlair workflow log-investigation access.log`
- **THEN** the workflow output includes a "Sigma matches" section with rule names, levels, and MITRE techniques

#### Scenario: Custom rule pack via flag
- **WHEN** the user runs `vlair workflow log-investigation access.log --sigma /opt/sigma`
- **THEN** the Sigma step uses the user-supplied directory instead of the bundled pack

### Requirement: CLI flags for Sigma analysis

The `vlair log analyze` and `vlair analyze` commands SHALL accept `--sigma <path|builtin>` and `--sigma-min-level <informational|low|medium|high|critical>` flags.

#### Scenario: Min-level filter
- **WHEN** the user runs `vlair log analyze access.log --sigma builtin --sigma-min-level high`
- **THEN** only matches at level `high` or `critical` appear in the alerts list
