## 1. Dependencies and bundled assets

- [ ] 1.1 Add `pySigma>=0.10,<0.12` as a new optional dep `[sigma]` in `pyproject.toml`; include in `[all]`
- [ ] 1.2 Create `src/vlair/data/sigma_rules/` directory; commit ~50 curated rules from SigmaHQ with attribution `LICENSE` file
- [ ] 1.3 Create `src/vlair/data/sigma_field_map.yml` mapping common Sigma fields to vlair event fields
- [ ] 1.4 Tests: validate the field-map file loads and contains entries for all bundled-pack rule fields

## 2. Sigma engine

- [ ] 2.1 New `tools/sigma_engine.py` with `SigmaEngine` class: `__init__(rule_paths, field_map_path, min_level)`
- [ ] 2.2 Rule loader: walks paths, parses with pySigma, captures parse errors per file
- [ ] 2.3 Field-mapping resolver: rejects rules with unmapped fields, populates `skipped_rules`
- [ ] 2.4 Modifier evaluators: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, `any`, comparison operators
- [ ] 2.5 Condition evaluator: walks pySigma's condition AST (selections, logical ops, `1/all of`)
- [ ] 2.6 De-duplication per `(rule_id, src_ip)` with `match_count` and event window
- [ ] 2.7 Tests: per-modifier unit tests; condition combinations; rule-loading edge cases

## 3. LogAnalyzer integration

- [ ] 3.1 Update `LogAnalyzer.analyze_file()` signature: `sigma_rules: Optional[Path | List[Path] | "builtin"] = None`
- [ ] 3.2 When set, instantiate SigmaEngine and call `evaluate(event)` per parsed event
- [ ] 3.3 Append matches to `alerts` list with `source="sigma"`; pattern-based alerts get `source="pattern"`
- [ ] 3.4 Result schema: `sigma_rules_loaded`, `sigma_rules_evaluated`, `skipped_rules`
- [ ] 3.5 Tests: regression — without sigma_rules, output identical; with sigma_rules, alerts grow

## 4. Risk-score integration

- [ ] 4.1 `core/scorer.py` reads `alerts` and adds Sigma level → score per the design's mapping
- [ ] 4.2 Cap at 100; max-of-levels semantics
- [ ] 4.3 Tests: combinations of levels produce expected scores

## 5. CLI

- [ ] 5.1 `vlair log analyze --sigma <path|builtin>` and `--sigma-min-level <level>`
- [ ] 5.2 `vlair analyze` (smart mode) auto-detects `.log` and applies the same flags
- [ ] 5.3 New subcommand `vlair sigma test <rule.yml> <event.json|-->` for rule authors
- [ ] 5.4 Console output: dedicated "Sigma matches" section above pattern matches
- [ ] 5.5 Tests: each CLI flag round-trips into the engine; `vlair sigma test` exit codes 0/1

## 6. Workflow integration

- [ ] 6.1 `workflows/log_investigation.py` adds a "sigma_evaluation" step before the existing pattern step
- [ ] 6.2 Step uses the bundled pack; honors `--sigma` flag override
- [ ] 6.3 Workflow report (markdown/html) renders Sigma matches with rule links
- [ ] 6.4 Tests: workflow runs end-to-end on a fixture log file

## 7. Webapp

- [ ] 7.1 `POST /api/log/analyze` accepts `sigma_rules` field; uses `_validate_path` for filesystem paths
- [ ] 7.2 Response includes Sigma-related fields documented in the log-analysis spec
- [ ] 7.3 SPA log analysis result page renders a Sigma matches table with severity color-coding
- [ ] 7.4 Tests: webapp endpoint returns expected schema; SPA component renders both empty and populated states

## 8. Performance and benchmark

- [ ] 8.1 Benchmark fixture: 100k synthetic events × 50 rules; target <30s on a laptop
- [ ] 8.2 Index rules by required field set to short-circuit unmapped events
- [ ] 8.3 Tests: benchmark in `tests/test_sigma_engine.py` with `pytest -m benchmark` (skipped by default in CI)

## 9. Documentation

- [ ] 9.1 New `docs/SIGMA.md`: bundled pack contents, field map, supported modifiers, authoring tips
- [ ] 9.2 Update `docs/INDEX.md` with `--sigma` flag and `vlair sigma test`
- [ ] 9.3 Update `README.md` with a one-line Sigma example
- [ ] 9.4 Add inline link from log-investigation workflow output to `docs/SIGMA.md`
