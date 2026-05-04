## Context

vlair's data layer evolved as single-tenant. Tables under `~/.vlair/*.db` carry no tenant key. Webapp endpoints scope by `g.current_user["id"]` only. The investigation engine writes to `investigations.db` without a tenant column. The AI cache is keyed by content hash and shared across all callers. This is fine for one team but unsafe the moment a second customer's data sits in the same database.

The connector framework (`investigate/connectors/`) is already abstract; it can adapt without an API break. The webapp uses a Flask app factory and `g.current_user` for context — adding `g.workspace_id` is the smallest possible surgery. The CLI runs as a single user with no auth, but it does load `~/.vlair/*.db` paths — a `--workspace` flag plus `VLAIR_WORKSPACE` env var is the natural extension.

## Goals / Non-Goals

**Goals:**
- Hard isolation of all tenant-scoped data at the SQL layer (every query has `WHERE workspace_id = ?`).
- Zero-data-loss migration from current single-tenant deployments.
- A single user can belong to multiple workspaces with different roles per workspace.
- API tokens are workspace-scoped — leaking a token compromises one workspace, not the whole instance.
- Backwards-compatible CLI: existing scripts that don't pass `--workspace` continue to work against the `default` workspace.

**Non-Goals:**
- Per-workspace resource quotas (separate change).
- Cross-workspace search / global "super-admin" view (deferred to a future capability).
- Workspace-scoped AI provider credentials.
- Row-level encryption per workspace.
- Workspace deletion that cascades to filesystem artifacts beyond SQLite (e.g., uploaded PCAPs in tempdir aren't tagged today; out of scope).

## Decisions

### D1. Workspace identity is a UUID, not a slug

Slugs are user-friendly but mutable. Foreign keys must be stable. Solution: store `workspace_id UUID PRIMARY KEY`, plus a separate `slug TEXT UNIQUE` column users can rename. APIs accept either form on input; URLs use the slug.

**Alternatives considered:** Auto-increment integer (rejected: predictable IDs leak workspace count, risky in MSSP context). Hash-based deterministic ID (rejected: complicates rename).

### D2. JWT carries `workspace_id` as a top-level claim

Add `wsid` to the JWT payload alongside `sub` and `role`. Tokens are workspace-scoped: a user with access to two workspaces holds two tokens (or refreshes to switch). The `role` claim becomes the user's role *in that workspace*, not a global role.

**Alternatives considered:** Server-side workspace selection per request via header (rejected: every request would require a DB lookup to validate membership; JWT amortizes that to login).

### D3. Migration via SQLite `PRAGMA user_version`

On webapp/CLI startup, check `PRAGMA user_version`. If `< 2`, run the v2 migration: create `workspaces` and `workspace_members` tables, insert one `default` workspace, add `workspace_id` columns to existing tables with the default workspace UUID as the value, set `PRAGMA user_version = 2`. Backfill is idempotent.

**Alternatives considered:** Alembic / a migration framework (rejected: SQLite-only deployment, single-file DB, the project has stayed framework-light intentionally).

### D4. Query enforcement via a thin DB wrapper, not raw SQL discipline

Introduce `webapp/auth/scoped_db.py` exposing `scoped_query(sql, params)` that auto-injects `WHERE workspace_id = ?` (or rejects if the SQL already has it). Every webapp call site uses this wrapper. A `flake8` plugin (or simple grep-based pre-commit hook) flags raw `conn.execute("SELECT ... FROM <scoped_table>")` in `webapp/`.

**Alternatives considered:** SQLAlchemy session events (rejected: adds heavy dependency to a sqlite-only codebase). View-based isolation via a per-tenant temp view (rejected: SQLite views aren't scoped per connection cleanly).

### D5. CLI defaults to user's primary workspace

`vlair` reads `VLAIR_WORKSPACE`, falls back to `~/.vlair/cli_config.json` `primary_workspace`, falls back to `default`. The CLI has no auth today; in single-user CLI deployments the user just runs against the `default` workspace and never notices the abstraction. MSSP CLI users explicitly set the env var per shell session.

### D6. Bot integrations bind a Slack channel / Teams channel to a workspace at install time

`bot_context.py` already stores per-channel state in SQLite. Add a `workspace_id` column. The Slack OAuth install handler asks the installer which workspace to bind. Channel users inherit that workspace's permissions transparently.

### D7. Default-deny test fixture

The pytest fixture `client` raises if a test calls a scoped endpoint without setting `g.workspace_id`. Forces every test to be tenant-aware and prevents new bugs.

## Risks / Trade-offs

- [Risk] Migration on a 5 GB single-tenant audit log will block startup for minutes. → Mitigation: chunked backfill with `LIMIT 5000 OFFSET ?`; emit a progress log; document expected duration in the deployment guide.
- [Risk] A missed query becomes a silent data leak between tenants. → Mitigation: D4 wrapper + lint check + test_tenant_isolation suite that creates two workspaces, writes data to one, asserts the other can't see it.
- [Risk] AI cache key collision lets one workspace see another's cached answer. → Mitigation: prepend `workspace_id` to the cache key hash input.
- [Risk] Existing API key holders lose access at upgrade time. → Mitigation: backfill API keys to the `default` workspace; existing keys keep working unchanged.
- [Risk] JWT size grows; `wsid` adds 36 bytes per token. → Mitigation: acceptable; well under the 8 KB header limit.
- [Trade-off] Switching workspaces requires a token refresh round-trip. Worth it: avoids per-request membership lookup.

## Migration Plan

1. Land schema migration code behind a feature flag (`VLAIR_MULTITENANT=true`). Default off — existing tests stay green.
2. Land scoped_db wrapper and start migrating endpoints; keep raw queries working.
3. Migrate every endpoint (one PR per area: auth, tools, admin, investigations).
4. Flip the flag default to `true`; existing deployments auto-migrate on startup.
5. Two releases later, remove the flag and the legacy code paths.

**Rollback:** `PRAGMA user_version` is reversible if no v2 schema is in production yet. Once a deployment has run on v2, rollback requires a backup restore (documented).

## Open Questions

- Does the CLI need a `vlair workspace switch <slug>` subcommand, or is the env var enough? (Recommendation: env var only for v1; subcommand if users complain.)
- Should `workspace_admin` be allowed to invite *new* (non-existing) users, or only existing ones? (Recommendation: existing only for v1; account creation stays at the platform admin level.)
- Slack channel-to-workspace binding: per-channel or per-team? (Recommendation: per-channel — finer-grained, matches existing bot_context schema.)
