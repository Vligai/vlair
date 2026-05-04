## Why

Sigma is the de-facto open detection format. Tens of thousands of community rules exist across the SigmaHQ repo, vendor releases, and threat intel reports. vlair's `log_analyzer` today ships with hand-written regex detectors for SQL injection, XSS, brute-force, and a handful of other patterns — useful, but capped at what we can author. Supporting Sigma instantly multiplies the detection coverage of `vlair workflow log-investigation` and `vlair analyze <log>` by a factor of hundreds, with zero ongoing rule-writing effort. It also positions vlair to be a viable analyst-side log triage tool when full SIEM access is unavailable.

## What Changes

- New `tools/sigma_engine.py`: loads Sigma YAML rules, compiles them to Python matchers, and applies them to parsed log events.
- `LogAnalyzer.analyze_file()` gains a `sigma_rules: Optional[Path | List[Path]]` argument. When set, every parsed event is checked against compiled rules and matches are added to the result `alerts` list with rule metadata (id, level, tags, references).
- New CLI flag `vlair log analyze --sigma <path>` (path may be a single rule, a directory, or a Git URL pointing at a rules repo).
- Rule loading supports recursive directory walk, `*.yml`/`*.yaml` files, and a built-in default rule pack at `src/vlair/data/sigma_rules/` (mirrors the existing `data/yara_rules/` pattern).
- Sigma backend supports the subset of Sigma needed for vlair's parsed-log model: `selection`/`condition` blocks, modifiers (`contains`, `startswith`, `endswith`, `re`, `cidr`, `all`), product/category fields routed to vlair's normalized event schema.
- Match results include `mitre_attack` techniques pulled from Sigma rule tags, feeding the existing AI summarizer and report generator.
- Webapp endpoint: `POST /api/log/analyze` accepts an optional `sigma_rules` field (path or rule pack name).
- New `vlair sigma` subcommand: `vlair sigma test <rule.yml> <log.json>` evaluates a single rule against a single event for rule authors.
- Updated `workflows/log_investigation.py` runs default Sigma rules as a step.

## Capabilities

### New Capabilities
- `sigma-detection`: Sigma rule loading, compilation, evaluation, and result formatting.

### Modified Capabilities
- `log-analysis`: existing pattern-based detection extended with Sigma matching; result schema gains a `sigma_matches` array.
- `operationalize`: `vlair workflow log-investigation` invokes the Sigma engine as a default step.

## Non-goals

- Full Sigma backend coverage. The pySigma project supports dozens of backends (Splunk, Elastic, etc.) — we only need the in-process Python evaluator for parsed events.
- Authoring or curating new Sigma rules. We consume; we don't publish.
- Sigma rule auto-generation from observed traffic (potential future feature; tracked separately as F-4 YARA/F-31 actor profile).
- Real-time streaming evaluation. v1 is batch over a parsed log file.
- Performance-tuned compiled-bytecode matchers. Naive Python evaluation is fine for the analyst-triage scale (MB to low GB log files).

## Impact

- **Code**: new `tools/sigma_engine.py`, modifications to `tools/log_analyzer.py`, `cli/main.py`, `workflows/log_investigation.py`, `webapp/app.py`, `core/scorer.py` (Sigma rule level → risk score contribution).
- **Dependency**: `pySigma>=0.10` (or `pyyaml` + a hand-rolled subset evaluator if the dependency is too heavy — design.md decides).
- **Data**: bundled rule pack under `src/vlair/data/sigma_rules/` containing ~50 high-signal rules covering web attacks, brute force, suspicious commands, lateral movement.
- **Tests**: new `tests/test_sigma_engine.py` covering rule loading, compilation, modifier evaluation, condition combinations, MITRE tag extraction.
- **Docs**: new `docs/SIGMA.md`; updates to `docs/INDEX.md`.
