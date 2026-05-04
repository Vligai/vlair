## ADDED Requirements

### Requirement: Workspace lifecycle

The system SHALL support creating, listing, renaming, and deleting workspaces. Each workspace SHALL have a stable UUID primary key and a mutable, unique slug.

#### Scenario: Create workspace
- **WHEN** a platform admin POSTs `/api/admin/workspaces` with `{"slug": "acme-corp", "name": "Acme Corp"}`
- **THEN** the system creates a workspace, returns the new UUID and slug, and writes an audit row with `action="workspace_created"`

#### Scenario: Slug collision
- **WHEN** a platform admin attempts to create a workspace with a slug that already exists
- **THEN** the system returns 409 with an error message and does not create the workspace

#### Scenario: Rename workspace
- **WHEN** a platform admin or workspace_admin PUTs `/api/admin/workspaces/<uuid>` with a new slug
- **THEN** the slug is updated, the UUID is unchanged, and existing tokens continue to work

#### Scenario: Delete workspace
- **WHEN** a platform admin DELETEs `/api/admin/workspaces/<uuid>`
- **THEN** all rows scoped to that workspace are deleted (cascade), all tokens for that workspace are revoked, and the workspace is removed; the operation is irreversible without a backup

### Requirement: Workspace membership

The system SHALL support adding and removing users to/from workspaces with a per-workspace role.

#### Scenario: Add user to workspace
- **WHEN** a workspace_admin POSTs `/api/admin/workspaces/<uuid>/members` with `{"user_id": 42, "role": "analyst"}`
- **THEN** the user gains access to that workspace with the specified role; the assigning admin is recorded in the audit log

#### Scenario: Remove user from workspace
- **WHEN** a workspace_admin DELETEs `/api/admin/workspaces/<uuid>/members/<user_id>`
- **THEN** the user loses access, all their active tokens scoped to that workspace are revoked, and an audit row is written

#### Scenario: User belongs to multiple workspaces
- **WHEN** a user is a member of workspace A as `analyst` and workspace B as `admin`
- **THEN** their effective role is determined by the active workspace in the JWT claim, not by global state

### Requirement: Workspace switching

The system SHALL allow a user to switch the active workspace by exchanging credentials for a workspace-scoped token.

#### Scenario: Switch via login
- **WHEN** a user logs in with `{"username": ..., "password": ..., "workspace": "acme-corp"}`
- **THEN** the issued JWT includes `wsid` set to that workspace UUID and `role` set to the user's role in that workspace

#### Scenario: Switch via dedicated endpoint
- **WHEN** an authenticated user POSTs `/api/auth/switch-workspace` with `{"workspace": "umbrella-co"}`
- **THEN** the system verifies membership and returns a new access + refresh token with `wsid` updated; the old tokens remain valid until natural expiry unless explicitly revoked

#### Scenario: Switch to non-member workspace
- **WHEN** a user tries to switch to a workspace they do not belong to
- **THEN** the system returns 403 and writes an audit row with `action="workspace_switch_denied"`

### Requirement: Default workspace on first run

The system SHALL automatically create a `default` workspace when migrating from a single-tenant deployment, and SHALL backfill all existing rows to it.

#### Scenario: Migrate single-tenant deployment
- **WHEN** the webapp starts against a database with `PRAGMA user_version < 2`
- **THEN** a `workspaces` row with slug `default` is created, every scoped table gains a `workspace_id` column populated with the default workspace UUID, every existing user is added to `workspace_members` with their current role, and `PRAGMA user_version` is set to 2
