## 1. Schema and entity

- [ ] 1.1 New `approvals` table with index on `(status, expires_at)`
- [ ] 1.2 New `approval_actions` association linking approvals to investigation steps
- [ ] 1.3 Migration writes; documented rollback (drop tables — no data loss for existing flows)
- [ ] 1.4 Tests: schema migration idempotent

## 2. Approval service

- [ ] 2.1 `src/vlair/approvals/service.py` with `submit`, `approve`, `deny`, `expire_pending_sweep`, `cancel_for_investigation`
- [ ] 2.2 Two-person rule enforcement
- [ ] 2.3 Single-use enforcement (executed approvals cannot be replayed)
- [ ] 2.4 Expiration sweep on every list/show/decide
- [ ] 2.5 Tests: full lifecycle; expired approval cannot decide; replay returns 410

## 3. Connector framework gate

- [ ] 3.1 `requires_approval(operation, kwargs)` in `BaseConnector`
- [ ] 3.2 Gate intercepts and returns `PendingApprovalResult`
- [ ] 3.3 `dry_run=True` bypasses gate; read operations bypass gate
- [ ] 3.4 Misconfigured read operations logged at startup
- [ ] 3.5 Tests: gate fires for mutating; bypassed for read; dry-run consistent

## 4. Auth and roles

- [ ] 4.1 New `approver` role added to RBAC; hierarchy doc updated
- [ ] 4.2 `--no-approval` flag accepted by mutating CLI commands; gated to `admin`
- [ ] 4.3 Mandatory `--reason` for bypass; empty rejected
- [ ] 4.4 Tests: role hierarchy enforced; bypass-without-reason rejected

## 5. Notifications

- [ ] 5.1 Notification dispatcher: Slack webhook, SMTP email, generic webhook
- [ ] 5.2 On submission: notify approvers; on decision: notify requester
- [ ] 5.3 Dispatch failures recorded on the approval row
- [ ] 5.4 Tests: each channel; failure surfaces in UI; no PII leaked in messages

## 6. CLI

- [ ] 6.1 `vlair approvals list [--pending|--all] [--mine] [--json]`
- [ ] 6.2 `vlair approvals show <id>`
- [ ] 6.3 `vlair approvals approve <id> [--comment]`
- [ ] 6.4 `vlair approvals deny <id> [--comment]`
- [ ] 6.5 `vlair investigate continue <id>` resumes paused steps
- [ ] 6.6 Tests: each subcommand; exit codes; `--json` schema

## 7. Webapp endpoints

- [ ] 7.1 `GET /api/approvals` (filterable)
- [ ] 7.2 `GET /api/approvals/{id}`
- [ ] 7.3 `POST /api/approvals/{id}/approve`
- [ ] 7.4 `POST /api/approvals/{id}/deny`
- [ ] 7.5 SPA Approvals page (pending queue + recent decisions)
- [ ] 7.6 Tests: role gating; two-person rule on POST endpoints

## 8. Investigation engine

- [ ] 8.1 Step-status `paused`; investigation status `PARTIALLY_COMPLETED`
- [ ] 8.2 Engine resume hook on approval-decided event
- [ ] 8.3 Investigation closure cancels pending approvals
- [ ] 8.4 Verdict computation handles paused/failed-from-denial steps
- [ ] 8.5 Tests: end-to-end pause/approve/resume; pause/deny/fail; close-cancels-approvals

## 9. Threat-platform integration

- [ ] 9.1 Mark `misp.push` and `thehive.open` as approval-eligible
- [ ] 9.2 Post-completion hook handles paused via approval cleanly
- [ ] 9.3 `published_to` reflects pending state until approval decided
- [ ] 9.4 Tests: investigation auto-publish via approval

## 10. Configuration

- [ ] 10.1 `approvals` section in `~/.vlair/integrations.json` schema
- [ ] 10.2 Per-action expiration overrides; per-workspace defaults
- [ ] 10.3 `require_separate_approver` toggle; documented use cases
- [ ] 10.4 Tests: config loader; partial config; invalid action names

## 11. Documentation

- [ ] 11.1 New `docs/APPROVALS.md`: configuration, role setup, workflow walkthrough
- [ ] 11.2 Update `docs/SECURITY.md`: SOC2 CC6.1 / ISO 27001 A.9.4.1 mapping
- [ ] 11.3 Update `docs/CONTRIBUTING.md`: new mutating connector ops must declare approval-eligibility
- [ ] 11.4 Update `docs/INDEX.md` with `vlair approvals` commands and `approver` role
