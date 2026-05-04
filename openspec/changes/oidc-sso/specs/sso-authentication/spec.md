## ADDED Requirements

### Requirement: OIDC discovery and login initiation

The system SHALL initiate OIDC authentication via authorization-code flow with PKCE and SHALL fetch provider metadata from the OpenID discovery URL.

#### Scenario: Initiate login
- **WHEN** an unauthenticated user GETs `/api/auth/sso/login?provider=okta-prod`
- **THEN** the system fetches (or uses cached) discovery metadata, generates `state`, `nonce`, and PKCE `code_verifier`, persists them in the SSO session table keyed by an HMAC-signed cookie, and returns a 302 redirect to the IdP's authorization endpoint

#### Scenario: Unknown provider
- **WHEN** the user GETs `/api/auth/sso/login?provider=does-not-exist`
- **THEN** the system returns 404 with `{"error": "Unknown SSO provider"}`

#### Scenario: Discovery unreachable
- **WHEN** the IdP's discovery URL returns a non-200 status and no cached document is available
- **THEN** the system returns 503 with `{"error": "SSO provider unavailable"}` and writes an audit row

### Requirement: OIDC callback validation

The system SHALL validate the ID token signature against the IdP's JWKS, SHALL verify `iss`, `aud`, `exp`, `iat`, `nbf`, and `nonce`, and SHALL reject tokens that fail any of these checks.

#### Scenario: Successful callback
- **WHEN** the IdP redirects to `/api/auth/sso/callback?provider=okta-prod&code=...&state=...`
- **THEN** the system exchanges the code for tokens, validates the ID token, resolves or creates the local user via `(iss, sub)`, applies the group-to-role mapping, issues a vlair access + refresh token, and returns 302 to the SPA

#### Scenario: Invalid state
- **WHEN** the callback's `state` parameter does not match the value stored against the session cookie
- **THEN** the system returns 400 and writes a `sso_state_mismatch` audit row

#### Scenario: Invalid signature
- **WHEN** the ID token signature does not verify against any key in the JWKS
- **THEN** the system returns 401 and writes a `sso_invalid_signature` audit row

#### Scenario: Replay attempt
- **WHEN** the same authorization code is presented twice
- **THEN** the second request fails (the IdP rejects duplicate code use); vlair returns 400 and audit-logs the attempt

### Requirement: Just-in-time user provisioning

The system SHALL create a local `users` row on first SSO login, keyed by `(iss, sub)`, with `auth_mode='sso'` and `password_hash=NULL`.

#### Scenario: First SSO login
- **WHEN** a user authenticates via OIDC with an `(iss, sub)` pair not present in `users`
- **THEN** the system inserts a new row with the user's email and a generated username, sets `auth_mode='sso'`, applies the group → role mapping, and writes a `sso_user_provisioned` audit row

#### Scenario: Subsequent SSO login
- **WHEN** an existing SSO user logs in
- **THEN** the system updates `last_login` and `email` (in case it changed), re-applies the group → role mapping, and reuses the existing user_id

#### Scenario: Password login attempt against SSO-only user
- **WHEN** a user with `auth_mode='sso'` attempts to log in via `/api/auth/login`
- **THEN** the system returns 401 with `{"error": "Use SSO to log in"}` and does not leak account existence

### Requirement: Group-to-role mapping

The system SHALL map IdP group claims to vlair roles via a declarative configuration file, and SHALL apply the configured `default_role` (or reject the login) when no group matches.

#### Scenario: Mapped group
- **WHEN** the ID token contains a `groups` claim including `vlair-admins` and the mapping resolves it to `admin`
- **THEN** the user's role is set to `admin` for that session

#### Scenario: Multiple matching groups
- **WHEN** the ID token contains multiple groups that all map
- **THEN** the user receives the highest-privilege role among them

#### Scenario: No mapped group, default present
- **WHEN** no group in the claim matches and `default_role: viewer` is configured
- **THEN** the user is provisioned as `viewer`

#### Scenario: No mapped group, no default
- **WHEN** no group in the claim matches and no `default_role` is configured
- **THEN** the login is rejected with 403 and a `sso_no_role_match` audit row is written

### Requirement: Off-boarding sync

The system SHALL re-validate group membership on every access-token refresh and SHALL provide an admin-triggerable sync that revokes access for users no longer authorized in the IdP.

#### Scenario: Group revoked between refreshes
- **WHEN** an SSO user attempts to refresh their access token and the IdP no longer reports them in any mapped group (and no default_role is set)
- **THEN** the refresh fails with 401, all of that user's existing tokens are revoked, and a `sso_offboarded` audit row is written

#### Scenario: Admin-initiated sync
- **WHEN** an admin POSTs `/api/admin/sso/sync`
- **THEN** the system iterates active SSO users, queries the IdP userinfo endpoint for each, and revokes tokens for users whose groups no longer permit access; the response summarises `{"checked": N, "revoked": M}`

### Requirement: Local + SSO coexistence

The system SHALL allow local password authentication and OIDC authentication to coexist, with per-user `auth_mode` controlling which mechanisms are valid.

#### Scenario: Break-glass admin
- **WHEN** the deployment has at least one local admin user with `auth_mode='local'`
- **THEN** that user can log in via username + password + TOTP regardless of SSO state

#### Scenario: SSO-only deployment guard
- **WHEN** the deployment has zero local admin accounts and SSO is the only configured backend
- **THEN** the webapp refuses to start with a clear error message

### Requirement: SSO providers list endpoint

The system SHALL expose a public endpoint listing configured SSO providers so the SPA can render appropriate sign-in buttons.

#### Scenario: List providers
- **WHEN** an unauthenticated client GETs `/api/auth/sso/providers`
- **THEN** the response contains a JSON array of `{name, display_name, icon}` objects, one per configured provider; `client_secret` and other sensitive fields are not included

### Requirement: PKCE and TLS enforcement

The OIDC integration SHALL use PKCE for the authorization-code flow and SHALL refuse to start if its callback URL is not HTTPS in production.

#### Scenario: HTTP callback rejected at startup
- **WHEN** the deployment configures a callback URL with `http://` and `FLASK_ENV=production`
- **THEN** the webapp raises `RuntimeError` and refuses to start
