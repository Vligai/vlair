## ADDED Requirements

### Requirement: Sigma rule loading

The system SHALL load Sigma rules from a single file, a directory (recursively), or a list of paths. Files matching `*.yml` and `*.yaml` SHALL be parsed; files that fail to parse SHALL be skipped with a warning rather than aborting the analysis.

#### Scenario: Single rule file
- **WHEN** the user passes `--sigma rule.yml`
- **THEN** the system parses one rule and uses it for evaluation

#### Scenario: Directory walk
- **WHEN** the user passes `--sigma /path/to/rules/`
- **THEN** the system recursively discovers all `*.yml` and `*.yaml` files and parses each into a rule

#### Scenario: Malformed rule
- **WHEN** one rule in a directory fails to parse
- **THEN** the system logs a warning naming the file and continues loading the remaining rules; the analysis result includes a `skipped_rules` list with the failing file paths

#### Scenario: Bundled rule pack
- **WHEN** the user passes `--sigma builtin` (or omits the flag inside `vlair workflow log-investigation`)
- **THEN** the system uses the rule pack bundled at `src/vlair/data/sigma_rules/`

### Requirement: Field mapping

The system SHALL apply a declarative Sigma-field-to-vlair-field mapping when evaluating rules. Rules referencing unmapped fields SHALL be skipped with a clear warning rather than producing incorrect results.

#### Scenario: Mapped field
- **WHEN** a Sigma rule references `c-ip` and the mapping resolves it to vlair's `src_ip`
- **THEN** rule evaluation reads the event's `src_ip` value

#### Scenario: Unmapped field
- **WHEN** a Sigma rule references `EventID` and no mapping is configured for that field
- **THEN** the rule is skipped, the warning includes the rule ID and the missing field, and the analysis result's `skipped_rules` list grows by one

### Requirement: Modifier evaluation

The system SHALL evaluate the Sigma modifiers `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, `any`, `lt`, `lte`, `gt`, `gte` correctly against vlair event fields.

#### Scenario: contains modifier
- **WHEN** a rule specifies `path|contains: '/admin'` and the event's `path` is `/admin/login`
- **THEN** the predicate evaluates true

#### Scenario: cidr modifier
- **WHEN** a rule specifies `src_ip|cidr: 10.0.0.0/8` and the event's `src_ip` is `10.5.1.2`
- **THEN** the predicate evaluates true

#### Scenario: re modifier
- **WHEN** a rule specifies `user_agent|re: '(?i)nikto|sqlmap'` and the event's `user_agent` is `Nikto/2.1`
- **THEN** the predicate evaluates true

### Requirement: Condition evaluation

The system SHALL evaluate Sigma `condition` expressions including `1 of <selection>`, `all of <selection>`, named selections combined with `and`/`or`/`not`, and nested parentheses.

#### Scenario: Conjunction
- **WHEN** a rule's condition is `selection_a and selection_b` and only `selection_a` matches
- **THEN** the rule does not fire

#### Scenario: 1-of expression
- **WHEN** a rule's condition is `1 of selection_*` with three selections, one of which matches
- **THEN** the rule fires

### Requirement: Match output

Each Sigma match SHALL include the rule ID, name, level, MITRE ATT&CK techniques, tags, source rule path, and the event that triggered it.

#### Scenario: Match with MITRE tag
- **WHEN** a rule with `tags: [attack.command_and_control, attack.t1071.001]` fires
- **THEN** the emitted match includes `mitre_attack: ["T1071.001"]` and `tags: ["attack.command_and_control"]`

### Requirement: Risk-score contribution

The system SHALL contribute Sigma rule levels to the existing risk scorer using a fixed mapping: `informational=5, low=15, medium=35, high=65, critical=90`. The contribution SHALL be the maximum level seen across matches, capped at 100.

#### Scenario: Single high match
- **WHEN** one rule with level `high` fires
- **THEN** the Sigma contribution to the risk score is 65

#### Scenario: Multiple matches, max wins
- **WHEN** rules with levels `medium`, `medium`, and `critical` fire
- **THEN** the Sigma contribution is 90, not 35+35+90

### Requirement: Per-rule rate limiting

The system SHALL de-duplicate matches per `(rule_id, src_ip)` within a single analysis run so that one noisy attacker does not flood the alerts list with thousands of identical matches.

#### Scenario: Repeated matches collapsed
- **WHEN** the same rule fires 500 times for the same `src_ip`
- **THEN** the alerts list contains a single entry with `match_count: 500` and a `first_event` / `last_event` window

### Requirement: vlair sigma test command

The system SHALL provide a CLI subcommand `vlair sigma test <rule.yml> <event.json>` (or `<event_json>` from stdin) that evaluates a single rule against a single event and reports whether it matches and which selection branches fired.

#### Scenario: Match
- **WHEN** the rule's condition evaluates true against the event
- **THEN** the command exits 0 and prints `MATCH` plus the matching selections

#### Scenario: No match
- **WHEN** the condition evaluates false
- **THEN** the command exits 1 and prints `NO MATCH` plus a per-selection breakdown
