## ADDED Requirements

### Requirement: Approval entity and lifecycle

The system SHALL define an `Approval` entity with `id`, `action_type`, `target`, `payload`, `requester`, `status` (`pending` / `approved` / `denied` / `expired` / `executed` / `executed_with_warning` / `bypassed`), `approver`, `decided_at`, `decision_comment`, `expires_at`, `created_at`, and (when triggered by an investigation) `context_url`.

#### Scenario: Submission creates pending approval
- **WHEN** a senior_analyst triggers an approval-required action
- **THEN** an `Approval` row is created with `status="pending"`, `expires_at` set per configuration, and the action does NOT execute synchronously

#### Scenario: Approval transitions terminate at executed/bypassed/denied/expired
- **WHEN** an approval reaches a terminal status
- **THEN** subsequent approve/deny attempts return 410 Gone with the current status; the row is immutable except for the audit-tracked terminal transition

### Requirement: Two-person rule

The system SHALL refuse `approve` or `deny` calls where `approver_id == requester_id`. The check SHALL be enforced server-side. When workspace configuration sets `require_separate_approver: false`, the rule is relaxed but every self-decision is recorded as `self_approved: true` in the audit log.

#### Scenario: Self-approval blocked by default
- **WHEN** the requester is also a member of the `approver` role and attempts to approve their own pending approval
- **THEN** the response is 403 with `error="two_person_rule_violation"`; the approval remains pending

#### Scenario: Self-approval allowed for solo deployments
- **WHEN** workspace config sets `require_separate_approver: false` and the requester approves their own action
- **THEN** the action executes; the audit row records `self_approved: true`; the approval status is `executed`

### Requirement: Approval expiration

The system SHALL expire pending approvals once `now() > expires_at`. The default expiration window is 24 hours; configurable per workspace and overridable per action-type. Expired approvals SHALL NOT auto-execute. Expiration sweeps SHALL run at the start of every list/show/decide operation.

#### Scenario: Expired approval cannot be approved
- **WHEN** an approver attempts to approve a pending approval after `expires_at`
- **THEN** the system first transitions the row to `expired` (writing an audit row), then returns 410 Gone with `error="approval_expired"`; no action executes

### Requirement: Notifications on submission and decision

The system SHALL dispatch notifications via configured channels (Slack webhook, SMTP email, generic webhook) when an approval is submitted (to approvers) and when it is decided (to requester). Notification dispatch results SHALL be recorded; failed dispatches SHALL surface in the SPA on the affected approval.

#### Scenario: Submission notifies approvers
- **WHEN** a senior_analyst submits an action that requires approval, with Slack webhook configured
- **THEN** a Slack message is posted to the configured channel including `action_type`, `target`, `requester`, and a link to the SPA approval page

#### Scenario: Failed notification surfaces in UI
- **WHEN** the Slack webhook returns 5xx during dispatch
- **THEN** the approval row records `notification_failed: true` with the error; the SPA renders a "notification not delivered" badge for the approver to see

### Requirement: Approval auto-execution on approval

When an approval is approved (and not expired), the system SHALL invoke the original connector operation with the original payload, attach the execution result to the approval row, and transition status to `executed` (or `executed_with_warning` when the platform reports a non-fatal anomaly).

#### Scenario: Approved action executes
- **WHEN** an approver approves a pending `disable_user` for `alice@example.com`
- **THEN** the system invokes the Identity connector's `disable_user("alice@example.com")` operation, records the result, and the approval status becomes `executed`

#### Scenario: Approved action no-op at platform
- **WHEN** an approval is approved but the target user has already been disabled by another tool
- **THEN** the platform call returns the no-op response, the approval row stores the response, status becomes `executed_with_warning`, and the audit log includes the warning

### Requirement: Emergency bypass

Users with the `admin` role SHALL be able to invoke approval-required actions with `--no-approval --reason "<text>"`. The reason SHALL be required (empty rejected). Bypass SHALL write a high-severity audit row and increment a `bypass_count` metric.

#### Scenario: Admin bypass with reason
- **WHEN** an admin runs `vlair edr isolate-host --target host-id-9 --no-approval --reason "active ransomware detonation"`
- **THEN** the action executes immediately; an audit row with `severity=high, action="approval.bypass"` is written; the `bypass_count` metric increments

#### Scenario: Bypass without reason rejected
- **WHEN** an admin runs `--no-approval` without `--reason`
- **THEN** the command exits with `error: --reason is required when bypassing approval`; no action executes; no audit row written

### Requirement: CLI commands for approvals

The CLI SHALL expose `vlair approvals list [--pending|--all]`, `vlair approvals show <id>`, `vlair approvals approve <id> [--comment <text>]`, and `vlair approvals deny <id> [--comment <text>]`. Outputs SHALL render in console table format by default and `--json` SHALL produce structured output for scripting.

#### Scenario: List pending approvals
- **WHEN** an approver runs `vlair approvals list --pending`
- **THEN** stdout shows a table of pending approvals with id, action_type, target, requester, age, and time remaining

#### Scenario: Approve with comment
- **WHEN** an approver runs `vlair approvals approve APR-2026-05-04-XXXX --comment "verified with on-call lead"`
- **THEN** the approval transitions to approved, the comment is recorded, and the action executes

### Requirement: Webapp endpoints for approvals

The webapp SHALL expose `GET /api/approvals` (filterable by `status`, `action_type`, `requester`), `GET /api/approvals/{id}`, `POST /api/approvals/{id}/approve`, and `POST /api/approvals/{id}/deny`. Decide endpoints SHALL accept an optional `comment` field. The SPA SHALL include an "Approvals" page rendering the pending queue with one-click approve/deny.

#### Scenario: Approver decides via SPA
- **WHEN** an approver opens the SPA Approvals page, clicks Approve on a pending row, and confirms
- **THEN** `POST /api/approvals/{id}/approve` is called; the page refreshes; the row moves to "Recent decisions"; the action executes asynchronously

### Requirement: Read operations exempt from approval

The approval gate SHALL refuse to wrap any operation marked `read=True` by its connector. Misconfiguration that lists a read operation in the approval list SHALL be detected at startup and logged as a configuration warning; the operation SHALL execute without approval regardless.

#### Scenario: Misconfigured read in approval list
- **WHEN** workspace config lists `siem.search` as approval-required
- **THEN** the system logs `WARNING: read operation siem.search cannot be approval-gated; ignoring`; SIEM searches continue to execute without approval
