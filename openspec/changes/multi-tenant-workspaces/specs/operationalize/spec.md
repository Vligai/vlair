## ADDED Requirements

### Requirement: CLI workspace selection

The `vlair` CLI SHALL accept a `--workspace <slug>` flag and `VLAIR_WORKSPACE` environment variable. When neither is set the CLI SHALL use the user's primary workspace.

#### Scenario: Explicit flag
- **WHEN** the user runs `vlair --workspace acme-corp analyze suspicious.eml`
- **THEN** the analysis runs against workspace `acme-corp`'s threat feeds, history, and AI cache

#### Scenario: Environment variable
- **WHEN** `VLAIR_WORKSPACE=umbrella-co` is set and the user runs `vlair analyze 8.8.8.8`
- **THEN** the analysis runs against workspace `umbrella-co`

#### Scenario: Flag overrides env var
- **WHEN** both `VLAIR_WORKSPACE=acme-corp` and `--workspace umbrella-co` are present
- **THEN** the CLI uses `umbrella-co`

#### Scenario: Default workspace fallback
- **WHEN** neither flag nor env var is set and `~/.vlair/cli_config.json` has no `primary_workspace`
- **THEN** the CLI uses the workspace with slug `default`

### Requirement: Workspace shown in CLI output headers

Console output for `analyze`, `workflow`, and `investigate` commands SHALL display the active workspace slug in the header so users do not silently run against the wrong tenant.

#### Scenario: Workspace appears in console banner
- **WHEN** the user runs any analysis command
- **THEN** the first non-empty line of console output includes `Workspace: <slug>`
