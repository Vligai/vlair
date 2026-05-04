## Why

vlair currently runs as a single-tenant deployment: every user, threat feed, investigation, audit row, and AI cache entry lives in one shared namespace. MSSPs, consultancies, and SOCs that handle multiple customers cannot host their data in one vlair instance without leaking IOCs, history, or PII across tenants. The fix has been deferred long enough that the data model has spread the assumption to ~15 tables; the cost of retrofitting will only grow.

## What Changes

- New `workspace_id` column added to every tenant-scoped table (`users` becomes a join table; `audit_log`, `analysis_history`, `investigations`, `investigation_steps`, `threat_feed_iocs`, `ai_cache`, `revoked_tokens`, `backup_codes`, `api_keys` all gain `workspace_id`).
- New `workspaces` and `workspace_members` tables. A user belongs to N workspaces with a per-workspace `Role`.
- JWT access tokens carry the active `workspace_id`; switching workspaces requires re-authentication or a `/api/auth/switch-workspace` call that issues a new token.
- Every `webapp/` query is filtered by `g.workspace_id`. A query without that filter is a bug; a lint check enforces this.
- CLI gains `--workspace <slug>` (and `VLAIR_WORKSPACE` env var). Default is the user's primary workspace.
- Admin endpoints under `/api/admin/workspaces/*` for create/list/delete/rename. Workspace-scoped admin (`workspace_admin`) for in-workspace user management.
- **BREAKING**: SQLite schema migration on first launch. A `default` workspace is auto-created and all existing rows are backfilled to it. No data loss; existing single-tenant clients keep working.
- Bot integrations (Slack/Teams) bind a channel to a workspace at install time; commands run in that workspace's context.

## Capabilities

### New Capabilities
- `workspace-management`: workspace lifecycle (create/rename/delete), membership, and per-workspace role assignment.
- `tenant-isolation`: query-level enforcement that prevents cross-workspace data access at the data and API layers.

### Modified Capabilities
- `operationalize`: CLI gains `--workspace` flag; analyze/check/workflow/investigate commands honor it.
- `investigation-automation`: investigations and their state are workspace-scoped; connectors receive workspace context.

## Non-goals

- Workspace-level resource quotas (CPU, AI cost cap, storage). Tracked separately.
- Cross-workspace IOC sharing or "global threat feed" projection. A future capability.
- Per-workspace AI provider keys (every workspace inherits the deployment-level key for now).
- Hierarchical workspaces / sub-workspaces.
- UI workspace switcher in the SPA — minimal API exposure first; UI follows in a separate change.

## Impact

- **Code**: `webapp/auth/models.py`, every webapp endpoint, `cli/main.py`, `investigate/state.py`, `core/history.py`, `ai/cache.py`, `tools/threat_feed_aggregator.py` storage layer, `integrations/bot_context.py`.
- **Schema**: SQLite migration v1 → v2; backward-compatible read path during rollout.
- **Tests**: every test fixture must create a workspace; new test_tenant_isolation suite required.
- **Docs**: `docs/DEPLOYMENT.md` gains a "multi-tenant" section; `docs/INDEX.md` notes the `--workspace` flag.
- **Performance**: every query gains a `WHERE workspace_id = ?` clause; new indexes on `(workspace_id, ...)` prefixes.
- **Operational**: existing deployments migrate automatically on next start; no manual step.
