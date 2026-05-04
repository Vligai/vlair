## 1. Schema and migration

- [ ] 1.1 Add `workspaces` and `workspace_members` tables to `webapp/auth/models.py`
- [ ] 1.2 Add `workspace_id` columns to: `users`, `audit_log`, `api_keys`, `revoked_tokens`, `backup_codes`
- [ ] 1.3 Add `workspace_id` columns to: `analysis_history` (`core/history.py`), `investigations` and child tables (`investigate/state.py`), `threat_feed_iocs` (`tools/threat_feed_aggregator.py`), `ai_cache` (`ai/cache.py`), `bot_context` (`integrations/bot_context.py`)
- [ ] 1.4 Implement `migrate_to_v2()` that creates the `default` workspace, backfills all rows in chunks of 5000, sets `PRAGMA user_version = 2`
- [ ] 1.5 Test migration on a fixture DB containing v1 data; assert `user_version=2` and all rows have non-null `workspace_id`

## 2. Scoped query helper

- [ ] 2.1 Create `webapp/auth/scoped_db.py` with `scoped_query(sql, params, workspace_id)` that parses the SQL, asserts no existing `workspace_id` filter, and appends one
- [ ] 2.2 Unit tests for `scoped_query`: SELECT, UPDATE, DELETE, INSERT, joins; tests for rejection of unsafe SQL
- [ ] 2.3 Pre-commit hook (regex scan) flagging raw `conn.execute("...FROM <scoped_table>")` in `webapp/`

## 3. JWT and auth changes

- [ ] 3.1 Update `webapp/auth/utils.py` to accept and emit `wsid` claim in access and refresh tokens
- [ ] 3.2 Update `webapp/auth/decorators.py` `_resolve_user` to read `wsid`, set `g.workspace_id`, and 401 if absent
- [ ] 3.3 Update `webapp/auth/routes.py` login to accept optional `workspace` param and select the user's workspace; default to `primary_workspace`
- [ ] 3.4 Add `POST /api/auth/switch-workspace` endpoint with membership verification
- [ ] 3.5 Update `revoke_all_user_tokens` to support per-workspace revocation
- [ ] 3.6 Tests: token without wsid → 401; switch to non-member → 403; switch to member → new tokens; cross-workspace JWT cannot read other workspace's data

## 4. Workspace management endpoints

- [ ] 4.1 New blueprint `webapp/auth/workspace_routes.py` with create/list/rename/delete under `/api/admin/workspaces`
- [ ] 4.2 Membership endpoints: `POST/DELETE /api/admin/workspaces/<uuid>/members`
- [ ] 4.3 Tests: create with duplicate slug → 409; delete cascades to scoped tables; member add/remove revokes tokens

## 5. Endpoint migration

- [ ] 5.1 Migrate `/api/ioc/*`, `/api/hash/*`, `/api/intel/*`, `/api/url/*` to use `scoped_query`
- [ ] 5.2 Migrate `/api/log/*`, `/api/eml/*`, `/api/yara/*`, `/api/cert/*`, `/api/deobfuscate`, `/api/pcap/*` similarly
- [ ] 5.3 Migrate `/api/threatfeed/*`, `/api/carve/*`, `/api/admin/audit` similarly
- [ ] 5.4 Migrate `/api/ai/*` and AI cache key generation to include workspace_id
- [ ] 5.5 Tests: tenant_isolation suite — two workspaces, write to A, assert B sees zero results across every endpoint

## 6. CLI and integrations

- [ ] 6.1 Add `--workspace` arg and `VLAIR_WORKSPACE` env var to `cli/main.py`
- [ ] 6.2 CLI loads workspace UUID via slug, threads it through `analyzer`, `workflow`, `investigate` commands
- [ ] 6.3 Console output banner shows `Workspace: <slug>`
- [ ] 6.4 Bot integrations: per-channel `workspace_id` binding in `bot_context.py`; Slack OAuth handler asks for workspace at install
- [ ] 6.5 Tests: CLI flag overrides env; bot routes commands to bound workspace

## 7. Investigation engine

- [ ] 7.1 `investigate/state.py` reads/writes `workspace_id` on every operation
- [ ] 7.2 `WorkspaceContext` dataclass added; passed to all connector method calls
- [ ] 7.3 Mock connectors updated to accept context (no behavior change)
- [ ] 7.4 Tests: cross-workspace investigation lookup returns None and logs audit row

## 8. Documentation

- [ ] 8.1 Update `docs/DEPLOYMENT.md` with multi-tenant section: enabling, primary workspace, MSSP setup
- [ ] 8.2 Update `docs/INDEX.md` with `--workspace` flag note
- [ ] 8.3 Add `docs/openspec/specs/workspace-management.spec.md` and `tenant-isolation.spec.md` after archive

## 9. Rollout

- [ ] 9.1 Land all code behind `VLAIR_MULTITENANT=true` flag (default off)
- [ ] 9.2 Internal validation against staging deployment
- [ ] 9.3 Flip flag default to `true`
- [ ] 9.4 Two releases later: remove flag and legacy non-scoped code paths
