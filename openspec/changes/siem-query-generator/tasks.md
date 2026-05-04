## 1. Cache schema

- [ ] 1.1 Add `prompt_kind TEXT NOT NULL DEFAULT 'summary'` column to `ai_cache`
- [ ] 1.2 Migration backfills existing rows with `prompt_kind='summary'`
- [ ] 1.3 Update cache key derivation to include `prompt_kind`
- [ ] 1.4 Tests: existing summary cache reads still work; cross-kind isolation

## 2. Generator core

- [ ] 2.1 New `ai/query_generator.py` with `SIEMQueryGenerator(provider, cache)` class
- [ ] 2.2 Canonical IOC extraction from investigation result (privacy-stripped, sorted, deduplicated)
- [ ] 2.3 JSON envelope validation; one retry on parse failure
- [ ] 2.4 Fallback templated query path
- [ ] 2.5 Tests: happy path with mocked provider; parse-fail-retry; double-fail fallback

## 3. Per-dialect prompt templates

- [ ] 3.1 `ai/prompts/query_splunk.py`: system prompt + 5 few-shot examples
- [ ] 3.2 `ai/prompts/query_sentinel.py`: same shape
- [ ] 3.3 `ai/prompts/query_elastic.py`: same shape
- [ ] 3.4 `ai/prompts/query_sumo.py`: same shape
- [ ] 3.5 Per-dialect templated fallback queries (no AI required)
- [ ] 3.6 Tests: each prompt module exposes `build_prompt(...)` returning string + system message

## 4. Schema hints

- [ ] 4.1 Loader for `~/.vlair/siem_schemas.json` with validation
- [ ] 4.2 Hints injected into prompt context per dialect
- [ ] 4.3 Tests: with and without config, indexes/tables substituted correctly

## 5. CLI

- [ ] 5.1 New `vlair query` subcommand with all flags from the spec
- [ ] 5.2 Stdin support (`--from -`)
- [ ] 5.3 `--copy` integration with `pyperclip` (graceful skip if not installed)
- [ ] 5.4 Console output groups results per dialect with clear headings
- [ ] 5.5 Tests: each flag round-trips; exit codes; stdin happy path

## 6. analyze / workflow integration

- [ ] 6.1 Add `--siem-queries <dialect[,...]>` flag to `vlair analyze`
- [ ] 6.2 Add same flag to `vlair workflow`
- [ ] 6.3 Reporter renders "Suggested SIEM queries" section in console + markdown reports
- [ ] 6.4 Tests: section appears only when flag set

## 7. Webapp

- [ ] 7.1 `POST /api/query/generate` endpoint, role-gated to analyst
- [ ] 7.2 Cache check before AI call; response includes `cached: bool`
- [ ] 7.3 SPA "Pivot to SIEM" panel on investigation results page
- [ ] 7.4 Per-dialect tabs with copy button
- [ ] 7.5 Tests: endpoint schema; SPA component renders all four dialect tabs

## 8. Cost / dry-run

- [ ] 8.1 `estimate_cost(investigation, dialect)` method on the generator
- [ ] 8.2 `--dry-run` prints prompt + estimate without calling AI
- [ ] 8.3 SPA shows estimate before clicking Generate
- [ ] 8.4 Tests: cost estimate within ±20% of actual for fixture inputs

## 9. Documentation

- [ ] 9.1 New `docs/SIEM_QUERIES.md` with sample inputs + outputs per dialect
- [ ] 9.2 Update `docs/INDEX.md` with `vlair query` and the analyze/workflow flags
- [ ] 9.3 Add `~/.vlair/siem_schemas.json` config example to `docs/DEPLOYMENT.md`
