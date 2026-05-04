## ADDED Requirements

### Requirement: Investigation steps pause on pending approval

When a playbook step invokes a connector operation that returns `PendingApprovalResult`, the engine SHALL record the step status as `paused`, attach the `approval_id` to the step, and continue to subsequent steps that do not depend on the paused step's result. The investigation SHALL be marked `PARTIALLY_COMPLETED` until paused steps are resolved.

#### Scenario: Step paused waiting on approval
- **WHEN** a phishing playbook reaches a host-isolation step that triggers a pending approval
- **THEN** the step is recorded with `status="paused"` and `approval_id`; subsequent independent steps continue; the investigation is `PARTIALLY_COMPLETED` with `paused_steps` listed

### Requirement: Resume on approval decision

When an approval associated with a paused step is approved and the action executes successfully, the system SHALL update the step to `status="completed"` with the connector result. When denied or expired, the step SHALL transition to `status="failed"` with the decision reason. The investigation status SHALL recompute when all paused steps resolve.

#### Scenario: Approval approved → step resumes
- **WHEN** the host-isolation approval is approved and the EDR call succeeds
- **THEN** the paused step transitions to `completed`, its result is attached, and the investigation re-evaluates whether to transition to `COMPLETED`

#### Scenario: Approval denied → step fails
- **WHEN** the approval is denied with comment "false positive"
- **THEN** the paused step transitions to `failed` with the denial reason; the investigation continues toward `COMPLETED`; the verdict notes the un-remediated finding

### Requirement: Manual resume command

The CLI SHALL expose `vlair investigate continue <investigation_id>` that re-evaluates paused steps for an investigation, useful when an approval was decided after the initial CLI session ended.

#### Scenario: Resume after CLI session ended
- **WHEN** an analyst runs `vlair investigate phishing --file x.eml`, the CLI exits with paused steps, an approver later approves, and the analyst runs `vlair investigate continue INV-...`
- **THEN** the system re-evaluates the paused steps, finds the approved one, plays it back, and re-runs the verdict computation

### Requirement: Investigation closure cancels pending approvals

When an investigation transitions to a terminal state (`COMPLETED`, `CANCELED`, `ARCHIVED`), the system SHALL cancel all pending approvals associated with the investigation, transitioning them to `expired` with reason `investigation_closed`.

#### Scenario: Cancel investigation cancels approvals
- **WHEN** an analyst cancels an investigation that has 3 pending approvals
- **THEN** all 3 approvals transition to `expired` with reason `investigation_closed`; the audit log records each transition; no actions execute
