## Context

`tools/log_analyzer.py` parses Apache/Nginx/syslog into a normalized event dict (timestamp, source IP, user, path, method, status, payload). Detection today is a fixed list of regex predicates evaluated per event. Sigma rules express the same kind of "match these fields against these patterns under this condition" logic but in YAML. Compiling Sigma to in-Python matchers against the existing event schema is straightforward — the main design questions are dependency choice, field mapping, and how aggressively to compile.

The reference Sigma project, pySigma, has a clean abstraction: parse YAML → SigmaRule → backend converts to a target query language. We don't need a "target query language" — we want to evaluate the rule directly. pySigma exposes `SigmaCondition` and `SigmaDetection` objects that we can walk in-process. This avoids re-implementing the parser.

## Goals / Non-Goals

**Goals:**
- A naïve user runs `vlair log analyze --sigma access.log /opt/sigma-rules/web/` and sees rule-named alerts with MITRE tags.
- Rule pack ships with vlair so the toolchain is useful without an external download.
- Sigma rule level (`high`, `critical`) maps cleanly into the existing `core/scorer.py` risk score.
- Every match exposes the source rule for analyst review (rule path, ID, link).
- Backend evaluator covers the modifiers most rules use: `contains`, `startswith`, `endswith`, `re`, `cidr`, value lists, `all`/`any` modifiers, `1 of`/`all of` conditions.

**Non-Goals:**
- Translating Sigma → SPL/KQL/etc. (covered by the separate `siem-query-generator` change).
- Full Sigma 1.0 spec coverage. Rules using exotic field-source modifiers are skipped with a warning, not an error.
- Stream/tailing mode (file watcher). v1 is batch.
- Pre-compiling rules to native code or using a JIT.

## Decisions

### D1. Use pySigma for parsing, custom evaluator for matching

pySigma's parser is mature and handles the YAML edge cases. Writing our own would be time poorly spent. But pySigma ships backends that emit *queries*, not in-process matchers. Solution: parse with pySigma, walk the resulting `SigmaRule`/`SigmaDetection`/`SigmaCondition` structure with a small custom evaluator (~200 lines of Python).

**Alternatives considered:** Write our own YAML parser (rejected: re-invents pySigma badly). Use a Sigma-to-Python backend if one exists (rejected: nothing mature, and the few attempts produce eval-able code which is a security risk). Translate to a `dataset` library predicate tree (rejected: extra dependency, no advantage).

### D2. Field mapping is declarative

vlair's normalized event has `timestamp`, `src_ip`, `user`, `path`, `method`, `status`, `user_agent`, `payload`, `bytes`, `host`. Sigma rules use names like `c-ip`, `cs-uri-stem`, `cs-method`, `EventID`. A YAML mapping file (`src/vlair/data/sigma_field_map.yml`) translates from common Sigma field names to vlair fields. Rules that reference unmapped fields are skipped with a `WARN` and reported in the analysis result so the user knows the rule didn't apply.

**Alternatives considered:** Hard-coded mapping in Python (rejected: less hackable). Per-rule mapping (rejected: bad UX). Auto-derive from rule logsources (rejected: too lossy).

### D3. Rule pack is bundled, not auto-fetched

Network-isolated SOC environments are common. We bundle a curated pack (~50 rules) in `src/vlair/data/sigma_rules/`. Operators who want the upstream SigmaHQ pack point `--sigma /path/to/sigma-rules-clone`. We do NOT fetch from a Git URL at runtime in v1; that's a follow-up if there's demand.

**Alternatives considered:** Auto-download (rejected: supply-chain risk and offline-deployment hostility).

### D4. Match output format

Each match emits:

```json
{
  "rule_id": "abc123-...",
  "rule_name": "Suspicious User-Agent String",
  "level": "high",
  "mitre_attack": ["T1071.001"],
  "tags": ["attack.command_and_control"],
  "matched_event": { ... },
  "rule_path": "/opt/sigma/web/...yml",
  "rule_link": "https://github.com/SigmaHQ/sigma/blob/main/rules/web/..."
}
```

This integrates with the existing `alerts` list and the AI summarizer prompt builder.

### D5. Sigma level → vlair risk score

Mapping: `informational=5`, `low=15`, `medium=35`, `high=65`, `critical=90`. `core/scorer.py` adds the highest level seen across all Sigma matches, capped at 100. Repeated matches don't double-count beyond the first.

### D6. Rule pack curation criteria

Bundled pack inclusion criteria: (a) maps to vlair's normalized event fields without extension; (b) high signal for analyst triage (low false-positive rate based on community feedback); (c) covers the existing `log-investigation` workflow's targets — web attacks, brute force, suspicious user agents, internal recon, exfil patterns. Target ~50 rules; skew toward covering MITRE techniques rather than per-vendor specifics.

## Risks / Trade-offs

- [Risk] False positives flood the `alerts` list and overwhelm analysts. → Mitigation: bundled pack is curated for low FP; level filter on `vlair log analyze --sigma-min-level medium`; matches are de-duplicated per (rule_id, source IP) within a single analysis.
- [Risk] pySigma version churn breaks rule loading. → Mitigation: pin to `pySigma>=0.10,<0.12`; CI runs the test suite against the pinned version; if pySigma evolves backward-incompatibly, document migration in `docs/SIGMA.md`.
- [Risk] Performance: 1000 rules × 100,000 events = 100M rule evaluations per analysis. → Mitigation: index rules by their first-required field so unmapped events skip whole rule sets; benchmark in `tests/test_sigma_engine.py` with target <30s for 100k events × 50 rules on a laptop.
- [Risk] Bundled pack ages (new attack patterns appear, old rules deprecate). → Mitigation: refresh pack every 6 months; tag the pack version in `vlair --version` output so analysts know what they're running against.
- [Trade-off] Field mapping introduces a translation layer. Some rules will skip silently on unmapped fields. Acceptable; surfacing unmapped-field warnings in the analysis output keeps it visible.

## Migration Plan

1. Land `tools/sigma_engine.py` and unit tests against synthetic events.
2. Land `LogAnalyzer` integration (opt-in via `sigma_rules` argument); existing analysis behavior unchanged.
3. Land bundled rule pack and `data/sigma_field_map.yml`.
4. Update `workflows/log_investigation.py` to invoke Sigma as a default step (uses bundled pack).
5. Update CLI (`--sigma`, `--sigma-min-level`, `vlair sigma test`).
6. Update webapp endpoint and SPA log analysis result rendering.

**Rollback:** If pySigma proves problematic, revert to the modifier subset (rejected in D1) — design intentionally allows that escape hatch.

## Open Questions

- Should the bundled rule pack be sourced from the SigmaHQ repo (curated subset with attribution) or hand-authored? (Recommendation: SigmaHQ subset with `LICENSE` attribution; saves authorship effort and stays maintained.)
- Min Python version for pySigma? (Need to verify against vlair's `>=3.9` floor.)
- Should `vlair sigma test` accept stdin for the event JSON? (Recommendation: yes — fits the CLI pattern of other tools.)
