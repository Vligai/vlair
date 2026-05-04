## ADDED Requirements

### Requirement: Identity connector category interface

The system SHALL define an `IdentityConnector` subclass of `BaseConnector` declaring `get_user(upn)`, `find_authentication_events(user, time_range)`, `disable_user(upn)`, and `force_password_reset(upn)`.

#### Scenario: Operations match abstract base
- **WHEN** the test suite invokes Identity connectors through the abstract interface
- **THEN** every concrete vendor returns DTOs with the same shape as `investigate/connectors/base.py:User` and `AuthenticationEvent`

### Requirement: Okta connector

An `OktaConnector(IdentityConnector)` SHALL implement Identity operations against Okta via the `okta` SDK. Authentication SHALL use a Okta API token. Installable via the `[okta]` extra.

#### Scenario: User lookup
- **WHEN** the playbook calls `identity.get_user("alice@example.com")` against a configured Okta connector
- **THEN** the connector queries `/api/v1/users/{login}` and returns a `User` DTO with `upn`, `display_name`, `mfa_enrolled`, `last_login`, `groups`

### Requirement: Microsoft Entra ID connector

An `EntraConnector(IdentityConnector)` SHALL implement Identity operations against Microsoft Entra ID via the Microsoft Graph SDK. Authentication SHALL use OAuth2 client_credentials. Installable via the `[entra]` extra (which shares the `msgraph-sdk` dependency with `[defender]`).

#### Scenario: Sign-in events
- **WHEN** the playbook calls `identity.find_authentication_events("alice@example.com", time_range="24h")` against a configured Entra connector
- **THEN** the connector queries the `auditLogs/signIns` endpoint and returns `AuthenticationEvent` DTOs

### Requirement: Identity write operations require senior_analyst

Operations that mutate user state (`disable_user`, `force_password_reset`) SHALL require the `senior_analyst` role. The framework SHALL enforce this before invoking the connector.

#### Scenario: Analyst attempting account disable
- **WHEN** a user with the `analyst` role triggers a step that would call `disable_user`
- **THEN** the step records `failed: insufficient_role`; no Identity API call is made; the audit log records the denial
