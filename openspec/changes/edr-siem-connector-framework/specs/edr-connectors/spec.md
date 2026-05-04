## ADDED Requirements

### Requirement: EDR connector category interface

The system SHALL define an `EDRConnector` subclass of `BaseConnector` declaring the operations `get_host(host_id)`, `get_processes(host_id, since)`, `isolate_host(host_id)`, `release_host(host_id)`, and `run_iocfeed_check(ioc, type)`. Each operation SHALL return the corresponding DTO declared in `investigate/connectors/base.py`.

#### Scenario: All EDR vendors implement the same surface
- **WHEN** the test suite invokes `EDRConnector` subclasses with the same input fixture
- **THEN** every vendor returns a DTO of the same shape; vendor-specific fields appear only in the optional `extensions` dict

### Requirement: CrowdStrike Falcon connector

A `FalconConnector(EDRConnector)` SHALL implement the EDR operations against the CrowdStrike Falcon API using the `crowdstrike-falconpy` SDK with OAuth2 client_credentials. The connector SHALL be installable via the `[crowdstrike]` extra.

#### Scenario: Host isolation
- **WHEN** the playbook calls `edr.isolate_host("device-id-1234")` against a configured Falcon connector
- **THEN** the connector calls the `hosts.PerformActionV2` endpoint with action `contain` and returns a `HostIsolationResult` with `isolated=True` on success

### Requirement: SentinelOne connector

A `SentinelOneConnector(EDRConnector)` SHALL implement the EDR operations against SentinelOne's Singularity API. Installable via the `[sentinelone]` extra.

#### Scenario: Process listing
- **WHEN** the playbook calls `edr.get_processes(host_id, since=datetime)` against a configured SentinelOne connector
- **THEN** processes from the SentinelOne deep-visibility query are returned as a list of `Process` DTOs

### Requirement: Microsoft Defender for Endpoint connector

A `DefenderConnector(EDRConnector)` SHALL implement the EDR operations against Microsoft Defender for Endpoint via the Microsoft Graph SDK. Installable via the `[defender]` extra.

#### Scenario: IOC feed check
- **WHEN** the playbook calls `edr.run_iocfeed_check("evil.com", "domain")` against a configured Defender connector
- **THEN** Defender's threat intelligence API is queried and the result is returned as an `IOCFeedResult` DTO

### Requirement: EDR write operations require senior_analyst

Operations that mutate endpoint state (`isolate_host`, `release_host`) SHALL be permitted only when the calling principal has at least the `senior_analyst` role. The framework SHALL enforce this before invoking the connector.

#### Scenario: Analyst attempting isolation
- **WHEN** a user with the `analyst` role triggers a step that would call `isolate_host`
- **THEN** the step records `failed: insufficient_role`; no Falcon API call is made; the audit log records the denial
