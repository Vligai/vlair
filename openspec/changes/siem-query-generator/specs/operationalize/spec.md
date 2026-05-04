## ADDED Requirements

### Requirement: vlair query CLI subcommand

The CLI SHALL expose `vlair query` with the flags `--from <investigation_id|->`, `--siem <dialect[,...]>`, `--time-range <range>`, `--copy`, `--out <file>`, `--no-ai`, `--dry-run`.

#### Scenario: Generate from investigation ID
- **WHEN** the user runs `vlair query --from INV-2026-05-03-XXXX --siem splunk --time-range 7d`
- **THEN** the SPL query is printed to stdout with explanation and warnings

#### Scenario: Generate from stdin
- **WHEN** the user pipes a JSON investigation result on stdin and runs `vlair query --from - --siem sentinel`
- **THEN** the query is generated against the piped input

#### Scenario: Multiple dialects
- **WHEN** the user passes `--siem splunk,sentinel,elastic`
- **THEN** stdout contains three labeled sections, one per dialect

### Requirement: Suggested queries in analyze and workflow output

`vlair analyze` and `vlair workflow` outputs SHALL include a "Suggested SIEM queries" section when invoked with `--siem-queries <dialect[,...]>`. The section is omitted by default.

#### Scenario: Flag opts in
- **WHEN** the user runs `vlair analyze suspicious.eml --siem-queries splunk`
- **THEN** the analysis output ends with a "Suggested SIEM queries" section containing one Splunk query

### Requirement: Webapp endpoint for query generation

The webapp SHALL expose `POST /api/query/generate` accepting `{investigation_id, dialect, time_range}` and returning the structured query response. The endpoint SHALL require at least the `analyst` role and SHALL be subject to the same audit logging as other endpoints.

#### Scenario: Successful generation
- **WHEN** an analyst POSTs `{"investigation_id": "INV-...", "dialect": "splunk", "time_range": "7d"}`
- **THEN** the response is the structured query object with HTTP 200
