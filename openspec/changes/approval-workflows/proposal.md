## Why

Once vlair drives real EDR/Identity/Email systems via the connector framework, mutating actions (host isolation, account disable, message purge, MISP push) carry real-world blast radius. The current model — `senior_analyst` role gates the whole call — is too coarse for high-impact actions. Mature SOCs require approval workflows: one analyst proposes, another approves, the action executes only after approval, and every approval/denial is audit-recorded. This is also a SOC2 / ISO 27001 control many customers will require.

## What Changes

- New `approvals` capability: `Approval` entity with `id, action_type, target, payload, requester, status (pending/approved/denied/expired), approver, decided_at, expires_at`.
- **Approval-required actions**: each mutating connector operation (isolate_host, disable_user, force_password_reset, purge_message, submit_to_quarantine, MISP push, TheHive case open) is configurable as approval-required per workspace.
- **Submission flow**: when a senior_analyst triggers an approval-required action, the system creates a `pending` approval record and the action does NOT execute. The requester receives confirmation.
- **Approval flow**: approvers (configurable role: `approver`, defaults to a separate user from the requester) see pending approvals in the SPA and via `vlair approvals list`. They approve or deny with an optional comment.
- **Two-person rule**: an approver SHALL NOT be the same identity as the requester. Configurable: `require_separate_approver: true` (default).
- **Auto-execution on approval**: once approved, the system invokes the connector with the original payload. Execution result is attached to the approval record.
- **Expiration**: pending approvals expire after a configurable window (default 24 hours). Expired approvals do not auto-execute.
- **Notifications**: approvers receive a notification (Slack/email/webhook) on submission; requester receives a notification on decision.
- **Bypass for emergencies**: an `admin` role may submit `--no-approval` with an audit comment explaining why; the action executes immediately and is recorded as an emergency bypass.
- New CLI: `vlair approvals list [--pending|--all]`, `vlair approvals show <id>`, `vlair approvals approve <id> [--comment]`, `vlair approvals deny <id> [--comment]`.
- New webapp endpoints: `GET /api/approvals`, `GET /api/approvals/{id}`, `POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/deny`. SPA "Approvals" page shows pending queue with one-click approve/deny.
- New role: `approver` (between `senior_analyst` and `admin`). The role hierarchy is documented; an `approver` can approve actions but not bypass approval.
- Configuration in `~/.vlair/integrations.json` extended with an `approvals` section listing which actions require approval and the expiration window.

## Capabilities

### New Capabilities
- `approval-workflows`: approval entity, submission/approval/denial flow, two-person rule, expiration, notifications, emergency bypass, CLI/SPA/API surfaces.

### Modified Capabilities
- `connector-framework`: mutating connector operations check the approval gate before execution; if approval-required, the call returns a pending-approval indicator instead of executing.
- `investigation-automation`: investigation steps that would invoke approval-required connector ops pause and surface a pending approval; resume on approval, fail on denial.
- `auth-system`: new `approver` role added to the role hierarchy; documented and enforced.
- `threat-platform-integration`: MISP push and TheHive case open are approval-eligible actions.

## Non-goals

- Approval workflows for read-only operations. Reads stay unrestricted within role gates.
- Multi-step approval chains (action requires N approvers). Single approver is the v1 model; chains are a follow-up.
- Approval delegation / out-of-office routing. Approvers approve directly; OOO is handled by adding additional approvers to the workspace.
- ITSM ticket integration (auto-create ServiceNow / Jira ticket per approval). Tracked as future capability.
- Time-based auto-approval. Approvals always need a human decision (or bypass with audit).
- Approval-as-policy-engine. Static configuration in v1; OPA/Rego-style dynamic policy is a future capability.

## Impact

- **Code**: new `src/vlair/approvals/` package (`models.py`, `service.py`, `notifications.py`); modifications to `integrations/connectors/framework.py` (gate check), `investigate/engine.py` (step pause/resume), `cli/main.py` (new subcommand group), `webapp/app.py` (new endpoints + SPA page).
- **Schema**: new `approvals` table with index on `(status, expires_at)`; new `approval_actions` association table linking approvals to investigation steps when applicable.
- **Dependencies**: none beyond what's already in vlair.
- **Tests**: end-to-end test simulating submission → approval → execution; expiration test with mocked time; two-person-rule violation test; bypass-with-audit test.
- **Docs**: new `docs/APPROVALS.md` covering config, role setup, audit recipes; updates to `docs/SECURITY.md` for SOC2/ISO mapping; `docs/CONTRIBUTING.md` notes that new mutating connector ops must declare approval-eligibility.
