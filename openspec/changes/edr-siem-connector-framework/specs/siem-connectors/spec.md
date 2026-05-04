## ADDED Requirements

### Requirement: SIEM connector category interface

The system SHALL define a `SIEMConnector` subclass of `BaseConnector` declaring `search(query, time_range)`, `find_url_clicks(url, time_range)`, and `find_authentication_events(user, time_range)`. The `query` parameter accepts the dialect-native query string for the configured vendor.

#### Scenario: Dialect-native query
- **WHEN** the playbook passes an SPL query string to a Splunk connector
- **THEN** the query is executed verbatim; no cross-dialect translation is attempted

### Requirement: Splunk connector

A `SplunkConnector(SIEMConnector)` SHALL implement SIEM operations against the Splunk REST API via `splunk-sdk`. Authentication SHALL use a Splunk auth token. Installable via the `[splunk]` extra.

#### Scenario: Search returns events
- **WHEN** the playbook calls `siem.search('index=email "evil.com"', time_range="7d")` against a configured Splunk connector
- **THEN** events are returned as a list of `LogEvent` DTOs with normalized `timestamp`, `source`, `host`, and a vendor-specific `raw` field

### Requirement: Microsoft Sentinel connector

A `SentinelConnector(SIEMConnector)` SHALL implement SIEM operations against Microsoft Sentinel's Log Analytics workspace via `azure-monitor-query`. Authentication SHALL use Azure AD client credentials. Installable via the `[sentinel]` extra.

#### Scenario: KQL query
- **WHEN** the playbook calls `siem.search(kql_query, time_range="7d")` against a configured Sentinel connector
- **THEN** the query is executed against the configured workspace and rows are returned as `LogEvent` DTOs

### Requirement: Elastic connector

An `ElasticConnector(SIEMConnector)` SHALL implement SIEM operations against Elasticsearch 8+ via the official `elasticsearch` client. Authentication SHALL use API key or basic auth. Installable via the `[elastic]` extra.

#### Scenario: ESQL query
- **WHEN** the playbook calls `siem.search(esql_query, time_range="7d")` against a configured Elastic connector
- **THEN** the query is executed via the ES|QL endpoint (or DSL fallback if disabled in cluster) and rows are returned as `LogEvent` DTOs

### Requirement: Time range normalization

The SIEM connector framework SHALL accept time ranges as ISO duration strings (`"7d"`, `"24h"`) and convert to the vendor-native time-range format. Invalid time ranges SHALL fail before any API call.

#### Scenario: Invalid time range
- **WHEN** a playbook passes `time_range="forever"`
- **THEN** the connector raises `InvalidTimeRangeError` synchronously, the audit log records `outcome="error"`, and no SIEM API call is made
