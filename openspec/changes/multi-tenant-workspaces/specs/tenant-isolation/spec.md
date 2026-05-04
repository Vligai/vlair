## ADDED Requirements

### Requirement: Query-level workspace scoping

Every query against a tenant-scoped table SHALL include a `WHERE workspace_id = ?` clause. The system SHALL provide a `scoped_query` helper that auto-injects this clause and SHALL fail loudly on raw SQL bypasses.

#### Scenario: Scoped helper rejects unsafe SQL
- **WHEN** code calls `scoped_query("SELECT * FROM analysis_history", workspace_id)` and the SQL has no workspace filter
- **THEN** the helper auto-appends `WHERE workspace_id = ?` and binds the workspace UUID

#### Scenario: Lint catches raw query
- **WHEN** a contributor writes `conn.execute("SELECT * FROM analysis_history")` directly in `webapp/`
- **THEN** the pre-commit lint check fails with an error pointing to the line

### Requirement: JWT carries workspace context

Access tokens SHALL include `wsid` (workspace UUID) and `role` (workspace-scoped role) claims. Authorization decisions SHALL use these claims and not query the user's global role.

#### Scenario: Token without wsid is rejected
- **WHEN** a request presents a JWT without a `wsid` claim
- **THEN** the request is rejected with 401 and an audit row is written

#### Scenario: Cross-workspace request denied
- **WHEN** a request presents a JWT with `wsid=A` and the requested resource belongs to workspace B
- **THEN** the request returns 404 (not 403, to avoid leaking the existence of cross-workspace resources)

### Requirement: Audit log isolation

Audit log queries SHALL return only rows scoped to the caller's active workspace. Platform admins MAY view a cross-workspace audit log via a dedicated endpoint that requires elevated authentication.

#### Scenario: Workspace admin queries audit log
- **WHEN** a workspace_admin GETs `/api/admin/audit`
- **THEN** the response contains only audit rows where `workspace_id` equals their active workspace

#### Scenario: Platform admin cross-workspace query
- **WHEN** a platform_admin with step-up auth GETs `/api/platform/audit?workspace_id=<uuid>`
- **THEN** the response contains audit rows for the specified workspace; the access itself is logged in a `platform_audit` table

### Requirement: AI cache isolation

The AI response cache SHALL include workspace ID in its cache key so that cached AI responses are never shared across workspaces.

#### Scenario: Same input, different workspaces
- **WHEN** workspace A submits an IOC for AI analysis and the response is cached, then workspace B submits the same IOC
- **THEN** workspace B's request triggers a fresh AI call (cache miss) and the result is cached separately

### Requirement: Tenant isolation test suite

The system SHALL include automated tests that create two workspaces, write data to one, and assert the other cannot read it via any documented API surface.

#### Scenario: Read isolation test
- **WHEN** the test creates workspace A with an investigation, then queries with a token scoped to workspace B
- **THEN** the response contains zero matching investigations

#### Scenario: Write isolation test
- **WHEN** the test attempts to PATCH workspace A's investigation using a token scoped to workspace B
- **THEN** the response is 404 and no rows are modified
