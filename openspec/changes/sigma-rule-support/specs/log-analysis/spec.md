## ADDED Requirements

### Requirement: LogAnalyzer accepts Sigma rules

The `LogAnalyzer.analyze_file()` API SHALL accept an optional `sigma_rules` argument: `None`, a path, or a list of paths. When set, every parsed event SHALL be evaluated against the loaded rules and matches SHALL appear in the `alerts` list of the result.

#### Scenario: With Sigma rules
- **WHEN** `analyze_file("access.log", sigma_rules="/opt/sigma/")` is called
- **THEN** the result's `alerts` list contains both pattern-based and Sigma-based alerts; each alert carries a `source: "pattern" | "sigma"` field

#### Scenario: Without Sigma rules (default)
- **WHEN** `analyze_file("access.log")` is called with no `sigma_rules`
- **THEN** behavior is identical to the previous release (only pattern-based alerts)

### Requirement: Result schema includes sigma metadata

The analyzer result schema SHALL include `sigma_rules_loaded` (count), `sigma_rules_evaluated` (count after field mapping), and `skipped_rules` (list of `{path, reason}`) so analysts can see what ran.

#### Scenario: Skipped rules visible
- **WHEN** the analyzer loads 50 rules and skips 12 due to unmapped fields
- **THEN** the result has `sigma_rules_loaded: 50`, `sigma_rules_evaluated: 38`, and a `skipped_rules` list with 12 entries

### Requirement: Webapp endpoint accepts Sigma rules

`POST /api/log/analyze` SHALL accept a `sigma_rules` form/JSON field that is `null`, a server-side path validated by `_validate_path`, or the literal string `"builtin"` to use the bundled pack.

#### Scenario: Server-side path
- **WHEN** the request includes `sigma_rules: "/home/user/.vlair/sigma"` and the path passes validation
- **THEN** the analysis loads rules from that directory

#### Scenario: Builtin pack
- **WHEN** the request includes `sigma_rules: "builtin"`
- **THEN** the analysis uses the bundled rule pack
