## Why

Analysts run vlair to triage an artifact, then immediately switch to their SIEM to look for related activity in the broader environment. They re-type the IOCs they just analyzed into Splunk SPL, Sentinel KQL, Elastic ESQL, or Sumo Logic — by hand, often with subtle dialect mistakes. The vlair investigation result already carries all the data needed to write those queries; we just don't emit them. Closing this gap removes the most common manual handoff step in the analyst workflow and is a natural fit for the existing AI provider abstraction.

## What Changes

- New `ai/query_generator.py` module: `SIEMQueryGenerator(provider)` exposes `generate(investigation_result, target_dialect, time_range)` and returns a structured result with the query string, an explanation, and warnings about dialect-specific caveats.
- Supported dialects in v1: `splunk` (SPL), `sentinel` (KQL), `elastic` (ESQL / Lucene), `sumo` (Sumo Cheetah). Each has a dedicated prompt template at `ai/prompts/query_<dialect>.py`.
- New `vlair query` CLI subcommand: `vlair query --from <investigation_id> --siem splunk --time-range 7d` emits the query to stdout (default), copies to clipboard with `--copy`, or writes to a file with `--out`.
- `vlair analyze` and `vlair workflow` gain a post-step "Suggested SIEM queries" section in their default output and a `--siem-queries <dialect[,...]>` flag to control which dialects are generated.
- Webapp endpoint: `POST /api/query/generate` body `{investigation_id, dialect, time_range}` → `{query, explanation, warnings, dialect, generated_at}`. Cached in the AI cache (24h TTL).
- New SPA "Pivot to SIEM" panel on investigation results, showing tabs per configured dialect with a one-click "Copy query" button.
- AI prompt design: each dialect prompt teaches the model the dialect's quote/escape rules, time-range syntax, and common index/table names. Output is constrained to a JSON envelope to prevent free-form prose.
- Generated queries are hash-cached: `(investigation_result_hash, dialect, time_range) → query`.

## Capabilities

### New Capabilities
- `siem-query-generation`: AI-powered translation of vlair investigation results into target SIEM query languages with dialect-aware prompts, output validation, and caching.

### Modified Capabilities
- `ai-analysis`: existing AI layer gains a query-generation prompt family alongside the threat-summary prompts; cache schema supports the new prompt type.
- `operationalize`: `vlair analyze` and `vlair workflow` emit suggested SIEM queries by default.

## Non-goals

- Live SIEM execution. v1 generates queries; users run them in their SIEM. (Live execution belongs to the `edr-siem-connector-framework` change.)
- Custom SIEM dialect support (BigQuery, Snowflake, ClickHouse). v1 covers the four most common analyst SIEMs; others added on demand.
- Query optimization / index hint emission. The generated query is correct; optimization is the analyst's job.
- Two-way translation (SIEM query → vlair input). Out of scope.
- Bypassing the AI provider for "simple" cases. Even simple cases benefit from dialect-aware quoting; the cache makes repeated calls free.

## Impact

- **Code**: new `ai/query_generator.py` and `ai/prompts/query_<dialect>.py` files; modifications to `cli/main.py`, `core/analyzer.py`, `core/workflow.py`, `webapp/app.py`, `core/reporter.py` (output integration).
- **Schema**: `ai_cache` table gains a `prompt_kind` column (`summary` | `query` | future kinds).
- **Tests**: `tests/test_query_generator.py` with mocked AI provider; per-dialect golden-output tests using a fixed seed and a mock LLM.
- **AI cost**: query generation roughly doubles the AI cost per investigation when enabled. Disabled by default in CLI; opt-in via flag or webapp toggle.
- **Docs**: new `docs/SIEM_QUERIES.md` with sample inputs, expected outputs, and dialect notes.
