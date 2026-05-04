## Context

vlair's current authorization model is one-shot: role check passes, action executes. That works for read-mostly tools but breaks down once vlair starts driving production systems via the connector framework. A senior_analyst can quarantine the CEO's mailbox or isolate the domain controller in one CLI call. SOC2 CC6.1 and ISO 27001 A.9.4.1 both call for separation of duties on privileged operations; many customers will reject vlair without it.

The natural shape: a thin gate around mutating connector operations. The gate intercepts, materializes an `Approval`, returns a pending-state response. A second user resolves the approval. On approve, the gate replays the original call.

## Goals / Non-Goals

**Goals:**
- Mutating connector operations don't execute without approval (when configured).
- Two-person rule: requester ≠ approver, enforced server-side.
- Audit trail: every submission, approval, denial, expiration, and bypass is logged with full context.
- Notifications for both requester and approver — async, non-blocking.
- Emergency bypass exists, is admin-only, requires a written reason.
- Investigation engine surfaces pending approvals and resumes on decision; doesn't deadlock.

**Non-Goals:**
- Multi-approver chains or M-of-N approvals (defer).
- Dynamic policy (defer; static action-list is fine for v1).
- Auto-approval based on risk thresholds (defer; humans make every decision).
- Approval queue UIs beyond the SPA and CLI (no Slack interactive buttons in v1; just a notification + link).

## Decisions

### D1. Approval gate sits in the connector framework

```python
# In BaseConnector.call(...)
if self._requires_approval(operation, kwargs):
    approval_id = approvals_service.submit(
        action_type=f"{self.vendor_id}.{operation}",
        target=self._extract_target(operation, kwargs),
        payload=kwargs,
        requester=current_user(),
    )
    return PendingApprovalResult(approval_id=approval_id)
# else: proceed with normal call path
```

`PendingApprovalResult` is a typed response distinct from operation results. Callers (playbooks, CLI handlers, webapp endpoints) check for it and handle accordingly.

**Alternatives considered:** Gate at the CLI/endpoint layer (rejected: bypassed by direct connector use; would have to be replicated everywhere). Gate inside each connector operation method (rejected: 9 vendors × 5 operations = 45 places to add the check; one place is better).

### D2. Approval payload is opaque-but-replayable

The submitted approval stores `payload` as a JSON-serialized dict of the original `kwargs`. On approve, the service deserializes and re-invokes the same connector method with the same arguments. This means approvals are deterministic — no "the action changed between submission and approval" surprises.

If the system state changes between submission and approval (e.g., the user has already been disabled by another tool), the connector call will surface the platform's response (likely a 404 or "no-op") and the approval is recorded as `executed_with_warning`.

**Alternatives considered:** Snapshot system state at submission and warn on diff at approval (rejected: too much surface area; the platform's response is the source of truth). Re-evaluate the trigger condition at approval (rejected: requires every operation to declare its trigger; too much per-operation work).

### D3. Two-person rule enforced at decision time

The approval service checks `requester_id != approver_id` when an `approve` or `deny` call comes in. If they match, the call returns 403 with `error="two_person_rule_violation"`. The same identity cannot approve their own request even if they hold the `approver` role.

When `require_separate_approver: false` (configurable per workspace), the rule is relaxed — useful for solo-operator deployments — but the audit log records `self_approved: true` to make it visible.

**Alternatives considered:** Strict-only mode with no escape hatch (rejected: small SOCs run vlair with one analyst). Group-membership rule ("approver must be in different team") (rejected: workspace concept doesn't carry team affinity yet).

### D4. Pending approvals do not block CLI/playbook execution

When a CLI command triggers a pending approval, the command exits with a clear message:
```
Action submitted for approval: APR-2026-05-04-XXXX
Status: pending — awaiting approver
View: vlair approvals show APR-2026-05-04-XXXX
```

When a playbook step triggers a pending approval, the step is recorded as `paused` (not `failed`), the investigation continues, and the result includes a list of pending approvals that the analyst can resolve before final disposition.

**Alternatives considered:** Block CLI until decision (rejected: CLI sessions don't survive long approvals; ties up an analyst). Auto-resume playbook on approval via background worker (deferred: requires durable execution; v1 surfaces it for manual resume via `vlair investigate continue`).

### D5. Expiration is a polled sweep, not a scheduled job

A lightweight sweep runs at the start of every approval list/show/decide call: find rows where `status="pending" AND expires_at < now()`, set them to `expired`, write audit rows. This avoids the operational complexity of cron/celery for a check that doesn't need to be precise to the second.

**Alternatives considered:** Scheduled background job (rejected: adds infrastructure; sweep-on-access is good enough). Lazy expiration only on read (rejected: expired approvals would linger in the pending count until accessed).

### D6. Notifications are pluggable but minimal in v1

Notification channels: Slack webhook, email (via SMTP env config), generic webhook. Configured per workspace. v1 sends:
- On submission: notify all users with the `approver` role (or the configured approver list)
- On decision: notify the requester

Each notification is a simple message with a link to the SPA. No interactive Slack buttons in v1 — clicking the link opens the SPA where the approver authenticates and decides.

**Alternatives considered:** Slack interactive blocks with approve/deny buttons (rejected: requires inbound webhook auth, request signing, mTLS — too much for v1; a link suffices). MS Teams adaptive cards (deferred to follow-up).

### D7. Emergency bypass is admin-only with mandatory reason

`vlair <command> --no-approval --reason "<text>"` skips the approval gate. Available only to users with the `admin` role. The bypass writes a high-severity audit row and increments a `bypass_count` metric. The reason is required (empty string rejected).

**Alternatives considered:** No bypass (rejected: real emergencies happen; auditable bypass is better than no bypass). Time-limited bypass keys (deferred: complex; reason-with-audit is the right v1 trade).

### D8. Approval expiration window default and overrides

Default expiration: 24 hours. Configurable per workspace; configurable per action-type with a fallback chain (action override → workspace default → built-in default 24h). Action-types with high blast radius (e.g., `disable_user`) can have shorter expirations to reduce stale-approval risk.

### D9. No approval for read operations

Read operations (`get_host`, `find_recipients`, `search`) are never approval-gated, regardless of configuration. Even if an operator misconfigures the action list, the gate refuses to wrap a read operation. This is a hard-coded safety against accidental denial of service.

## Risks / Trade-offs

- [Risk] Approval queue overflow during incident response. → Mitigation: bypass-with-audit for true emergencies; per-action override of expiration; bulk-approve UI in SPA (defer).
- [Risk] Notifications fail silently. → Mitigation: notification dispatch result logged in audit; SPA shows "notification not delivered" badge on approvals where dispatch failed.
- [Risk] Approver phishing — attacker submits a malicious action and approves themselves via stolen approver creds. → Mitigation: two-person rule blocks self-approval (this is the whole point); MFA on approver accounts; audit alert on approver-from-new-IP.
- [Risk] Replay attack on approved payload — attacker captures approved action and re-submits later. → Mitigation: each approval has a single-use token; once executed, status is `executed`; replay attempts return 410 Gone.
- [Risk] Approval queue blocks active investigation. → Mitigation: investigations record paused steps and continue; analyst resumes after decision; no deadlock by design.
- [Risk] CLI users without SPA access can't be approvers. → Mitigation: full CLI approve/deny commands; `vlair approvals show` renders a TUI summary so a CLI-only approver has equivalent context.
- [Trade-off] Adding latency (24h ceiling) to mutating actions slows incident response. → Trade: this is the explicit ask from SOC2-conscious customers; we honor it and provide bypass for true emergencies.

## Migration Plan

1. Land approvals capability standalone: schema, service, CLI, SPA, API endpoints. Action list is empty by default — no operations are approval-gated yet.
2. Operators opt-in by editing `integrations.json` to add actions to the approval list. Initial deployments add only the highest-blast-radius actions.
3. Update `connector-framework` to invoke the gate; verify with mock connectors first, then real.
4. Update `investigation-automation` to handle paused-step semantics from pending approvals.
5. Update threat-platform-integration to mark MISP push and TheHive open as approval-eligible.
6. Document SOC2 mappings in `docs/SECURITY.md`.

**Rollback:** Set the action list to empty in config — gate becomes a no-op; mutating operations execute as before. Schema migration is additive; rollback is a no-op.

## Open Questions

- Should approvers see the original investigation context (link back) when approving an investigation-triggered action? (Recommendation: yes — approval payload includes `context_url` pointing to the investigation.)
- Should we auto-cancel a pending approval if the underlying investigation is closed? (Recommendation: yes — closing an investigation expires its pending approvals with reason `investigation_closed`.)
- How do we handle approvals during workspace deletion? (Recommendation: cascade — delete pending approvals with audit; workspace deletion is admin-only and rare.)
- Should the SPA support bulk approve for similar actions? (Recommendation: defer to a follow-up; v1 is per-approval.)
