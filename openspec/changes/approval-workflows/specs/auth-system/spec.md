## ADDED Requirements

### Requirement: Approver role

The system SHALL define an `approver` role between `senior_analyst` and `admin` in the role hierarchy. The role's sole privilege beyond `analyst` is to decide pending approvals. An `approver` MAY also hold other roles (e.g., `senior_analyst`); roles are additive.

#### Scenario: Role hierarchy ordering
- **WHEN** the role hierarchy is queried
- **THEN** the order is `viewer < analyst < senior_analyst < approver < admin`; `approver` does NOT inherit `senior_analyst` mutating capabilities by virtue of holding only `approver`

#### Scenario: Approver-only user can't trigger mutating actions
- **WHEN** a user with only the `approver` role attempts to trigger a mutating connector operation
- **THEN** the role check fails the same as for an `analyst` (insufficient role); the user can decide approvals but cannot create them

### Requirement: Admin bypass requires admin role

The `--no-approval` bypass flag SHALL be honored only when the calling principal has the `admin` role. Lower roles attempting `--no-approval` SHALL receive `error="bypass_requires_admin"` and the action SHALL NOT execute.

#### Scenario: senior_analyst attempts bypass
- **WHEN** a senior_analyst runs an approval-required action with `--no-approval --reason "..."`
- **THEN** the command fails with `bypass_requires_admin`; an audit row records the attempted bypass; no action executes

### Requirement: Audit trail for approval decisions

Every approval submission, approval, denial, expiration, bypass, and cancellation SHALL write an audit row including the approval_id, the principal, the action_type, the target, the timestamp, and the decision comment (when applicable). Audit rows SHALL be queryable via the existing `audit_log` interface.

#### Scenario: Audit query for an action
- **WHEN** an admin queries `audit_log` for `action="approval.*" AND target="alice@example.com"`
- **THEN** the result includes every approval lifecycle event affecting that user, in chronological order
