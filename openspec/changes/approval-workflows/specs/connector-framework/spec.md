## ADDED Requirements

### Requirement: Connector framework checks approval gate

`BaseConnector.call(operation, ...)` SHALL check the approval registry before invoking the underlying operation. When the operation is approval-required by configuration AND `dry_run=False`, the call SHALL submit an approval and return a `PendingApprovalResult` instead of executing.

#### Scenario: Mutating call returns pending approval
- **WHEN** a senior_analyst calls `edr.isolate_host("host-123")` with `isolate_host` configured as approval-required
- **THEN** the call returns `PendingApprovalResult(approval_id=..., status="pending")`; no API call is made to the EDR vendor

#### Scenario: Dry-run skips approval gate
- **WHEN** the same call is made with `dry_run=True`
- **THEN** the dry-run path executes (audit + synthetic response); no approval is submitted; the gate is bypassed because the action is not real

#### Scenario: Read operation not gated
- **WHEN** a call to `edr.get_host("host-123")` is made
- **THEN** the gate is not consulted; the read proceeds; this holds even if `get_host` is misconfigured into the approval list

### Requirement: PendingApprovalResult is a typed return

The framework SHALL define a `PendingApprovalResult` dataclass with `approval_id`, `status`, `expires_at`, and `view_url` fields. Callers (CLI, playbooks, webapp) SHALL detect this type and handle it distinctly from operation result DTOs.

#### Scenario: CLI surfaces pending approval clearly
- **WHEN** a CLI command receives a `PendingApprovalResult`
- **THEN** stdout shows `Action submitted for approval: APR-...`, the expiration time, and the view URL; exit code is 0 (the submission succeeded; the action did not execute, which is by design)
