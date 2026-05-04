## Context

The AI layer in `src/vlair/ai/` already does prompt-based threat summarization with a clean provider abstraction (Anthropic / OpenAI / Ollama), persistent SQLite cache, and a privacy-stripping pre-processor. The summarizer takes an investigation result and produces structured assessment JSON. This is exactly the shape of the SIEM-query problem: investigation result in, structured output (query + explanation + warnings) out, dialect-aware. Reusing the cache, provider abstraction, and privacy layer is the right move.

The four target dialects differ in non-trivial ways. SPL uses `index=foo` and `earliest=-7d`. KQL uses `union` and `ago(7d)`. ESQL is sql-flavored with `WHERE @timestamp > NOW() - INTERVAL 7 DAY`. Sumo Cheetah uses keyword search with `_index=foo`. Quoting rules differ. IOC list expansion differs. Time-range syntax differs. Encoding all of this in code would be brittle; a per-dialect prompt template lets the model handle the dialect particulars while we constrain its output.

Cost matters. Two AI calls per investigation (summary + queries) is a doubling of marginal cost. Cache aggressively.

## Goals / Non-Goals

**Goals:**
- A correct, runnable query in the user's chosen dialect, given a vlair investigation result.
- Cached per (input hash, dialect, time range) — repeat invocations free.
- Output schema includes both the query and a human explanation so the analyst can sanity-check before pasting into prod.
- Privacy-stripped input, same as the existing AI summarizer.
- Multiple dialects in one call: `vlair query --siem splunk,sentinel` returns both.

**Non-Goals:**
- Validating the query against a real SIEM (we don't run it).
- Customer-specific schema knowledge ("our Splunk uses sourcetype=our_corp_proxy"). Users provide their schema hints via flags or config.
- Streaming / live updates of the query as the investigation progresses.

## Decisions

### D1. Per-dialect prompt template, single shared evaluator

Each dialect gets its own file under `ai/prompts/query_<dialect>.py` with:
- A system prompt teaching the model the dialect's syntax, quote rules, time syntax, and the JSON output envelope.
- Few-shot examples (3–5) showing IOC list → query for that dialect.

The evaluator (`ai/query_generator.py`) is dialect-agnostic: takes an investigation result + dialect, picks the right prompt module, calls the provider, validates the JSON envelope, returns the structured result.

**Alternatives considered:** Single prompt with dialect as a variable (rejected: prompts get unwieldy and quality drops). Dialect-specific Python emitters with no AI (rejected: too brittle for evolving SIEMs and customer-specific schema).

### D2. Constrained JSON output

The model returns:

```json
{
  "query": "<dialect-specific query>",
  "explanation": "<2-3 sentences>",
  "warnings": ["<dialect caveats>"],
  "iocs_included": ["<each IOC the query references>"]
}
```

Validation happens before caching. If JSON parse fails or required fields are missing, the call retries once with a stricter prompt. Two failures → return an error with `fallback_query` (a templated, non-AI query) so the analyst still has *something* runnable.

**Alternatives considered:** Free-form text output with regex extraction (rejected: brittle). Tool-use / function-calling (rejected: not all providers support it consistently; would lock us out of Ollama).

### D3. Cache key includes dialect, time range, and `iocs_included` digest

`cache_key = sha256(dialect + time_range + canonical_iocs_json)` where `canonical_iocs_json` is the privacy-stripped, sorted, deduplicated IOC list extracted from the investigation result. Two investigations producing the same IOC set against the same dialect share a cache entry.

**Alternatives considered:** Cache by full investigation result hash (rejected: misses obvious cache hits when only non-IOC fields differ).

### D4. Time range is an explicit input, never inferred

The model is bad at picking a time range. Always ask the user (CLI flag, API field) and pass it as a structured input. Default: `7d`. Accept Splunk-style relative (`24h`, `7d`, `30d`) and absolute ISO ranges.

### D5. Dialect-specific schema hints in user config

Users may add `~/.vlair/siem_schemas.json`:

```json
{
  "splunk": {"index": "main", "sourcetype_mapping": {"proxy": "corp_proxy", "edr": "crowdstrike"}},
  "sentinel": {"workspace": "default", "table_mapping": {"proxy": "Proxy_CL"}}
}
```

The generator passes these to the prompt as additional context. With no hints, the model uses neutral placeholders (`<your_index>`).

### D6. Privacy and content sanitization

Reuse `ai/privacy.py` to strip RFC-1918 IPs, file contents, and any field flagged as sensitive before the prompt is built. The generator never sees raw bytes or internal hostnames unless explicitly opted in.

### D7. Fallback templated query

For each dialect, ship a hand-written template (Jinja2 or .format) that generates a "good enough" query without AI. Used when:
- AI unavailable / no API key configured.
- AI call fails twice.
- User passes `--no-ai` to `vlair query`.

The fallback is documented as "best-effort" and lacks the dialect polish of an AI output, but it always works.

### D8. Multi-dialect single call

`vlair query --siem splunk,sentinel,elastic` makes one call per dialect (parallelized). Cache hits skip the call entirely. Console output groups results under per-dialect headings.

## Risks / Trade-offs

- [Risk] Generated query references the wrong index/table for the customer's setup. → Mitigation: schema hints (D5); explanation includes "Adjust `index=...` to match your environment"; warnings call out neutral placeholders.
- [Risk] AI hallucinates a dialect feature that doesn't exist. → Mitigation: few-shot examples in the prompt; warnings list to flag uncertainty; the analyst always reviews before running.
- [Risk] Cost regression for users running many investigations. → Mitigation: opt-in by default in CLI; webapp toggle; aggressive cache; cost estimator visible before generation.
- [Risk] Prompt drift across model versions. → Mitigation: per-dialect golden output tests with mocked LLM; refresh tests when bumping model defaults.
- [Trade-off] Two AI calls per investigation cost more, but the cache hit rate after the first run is typically 80%+ for the same IOC set.

## Migration Plan

1. Land `ai/query_generator.py` and one dialect (Splunk) end-to-end with tests.
2. Add Sentinel, Elastic, Sumo dialects in subsequent PRs.
3. Add CLI flag and webapp endpoint behind opt-in flag.
4. Land SPA "Pivot to SIEM" panel.
5. Document `docs/SIEM_QUERIES.md` with examples per dialect.
6. After 4 weeks of usage, evaluate flipping default to "always emit Splunk query in `vlair analyze`" if AI cost permits.

**Rollback:** Feature is opt-in; disabling is a config flag flip. No schema migration to revert beyond the `prompt_kind` column on `ai_cache`, which is backward-compatible.

## Open Questions

- Should the generated query be auto-copied to clipboard by default, or require `--copy`? (Recommendation: `--copy` opt-in; clipboard access is platform-fragile.)
- Should we surface the model's confidence in the generated query? (Recommendation: yes, via the `warnings` list — explicit warnings are better than a numeric score the user can't act on.)
- Should query generation be available to `analyst` role or require `senior_analyst`? (Recommendation: `analyst` — the query is read-only output, no execution.)
- BigQuery / Snowflake support priority? (Defer until customers ask.)
