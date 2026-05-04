## ADDED Requirements

### Requirement: AI cache supports multiple prompt kinds

The `ai_cache` schema SHALL include a `prompt_kind` column distinguishing `summary` from `query` (and future kinds), so generations of different types do not collide on the same cache key.

#### Scenario: Cache isolation by kind
- **WHEN** an investigation has been summarized and a query for the same investigation is requested
- **THEN** the two cache rows are distinct (different `prompt_kind`) and neither call returns the other's result

### Requirement: Provider abstraction reused

The query generator SHALL invoke the AI provider via the existing `ai/providers/base.py` interface and SHALL respect the configured provider precedence (Anthropic → OpenAI → Ollama).

#### Scenario: Provider switch
- **WHEN** `VLAIR_AI_PROVIDER=ollama` is set and a query is generated
- **THEN** the request is sent to the local Ollama provider; no Anthropic or OpenAI calls are made

### Requirement: Cost estimation for query calls

The system SHALL estimate input + output tokens and dollar cost for a query-generation call before invocation, surfacing the estimate via `vlair query --dry-run` and the SPA UI.

#### Scenario: Dry-run shows estimate
- **WHEN** the user runs `vlair query --from <id> --siem splunk --dry-run`
- **THEN** stdout contains the estimated tokens, estimated cost in USD, and the prompt that would be sent (after privacy stripping); no AI call is made
