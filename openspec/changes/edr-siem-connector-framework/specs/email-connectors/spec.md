## ADDED Requirements

### Requirement: Email connector category interface

The system SHALL define an `EmailConnector` subclass of `BaseConnector` declaring `find_recipients(message_id)`, `purge_message(message_id, scope)`, and `submit_to_quarantine(message_id)`. The `scope` parameter accepts `"sender"`, `"recipient"`, or `"all"`.

#### Scenario: Operations match abstract base
- **WHEN** the test suite invokes Email connectors through the abstract interface
- **THEN** every concrete vendor returns DTOs matching `investigate/connectors/base.py:Email` shape

### Requirement: Microsoft Graph email connector

A `GraphMailConnector(EmailConnector)` SHALL implement Email operations against Exchange Online via the Microsoft Graph SDK. Authentication SHALL use OAuth2 client_credentials with the application permissions `Mail.ReadWrite` and `Mail.Send`. Installable via the `[graph]` extra (shared with `[defender]` and `[entra]`).

#### Scenario: Find recipients of a campaign
- **WHEN** the playbook calls `email.find_recipients(message_id)` against a configured Graph connector
- **THEN** the connector queries the `/messages` search endpoint scoped to the configured tenant and returns a list of recipient `Email` DTOs

#### Scenario: Purge a phishing message
- **WHEN** an authorized user triggers `email.purge_message(message_id, scope="all")`
- **THEN** the connector calls the Graph search-and-delete (or compliance search) flow and returns a `PurgeResult` with the count of mailboxes affected

### Requirement: Google Workspace email connector

A `GoogleWorkspaceConnector(EmailConnector)` SHALL implement Email operations against Gmail via the `google-api-python-client` Gmail API. Authentication SHALL use a service account with domain-wide delegation. Installable via the `[gws]` extra.

#### Scenario: Quarantine equivalent in Gmail
- **WHEN** the playbook calls `email.submit_to_quarantine(message_id)` against a configured Google Workspace connector
- **THEN** the connector applies the configured quarantine label to the message across all matching mailboxes (Gmail does not have a true quarantine; the documented behavior is label-based)

### Requirement: Email mutating operations require senior_analyst

`purge_message` and `submit_to_quarantine` SHALL require the `senior_analyst` role. The `find_recipients` read operation SHALL require at least the `analyst` role.

#### Scenario: Analyst attempting purge
- **WHEN** a user with the `analyst` role triggers a step that would call `purge_message`
- **THEN** the step records `failed: insufficient_role`; no email API call is made; the audit log records the denial
