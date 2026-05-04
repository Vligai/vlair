## Why

Enterprise procurement gates on SSO. vlair currently authenticates only against its local user table with a username + password + TOTP. Customers cannot enforce their corporate password policy, MFA factor (WebAuthn, smart card), session lifetime, conditional access rules, or off-boarding flows — the moment HR removes someone from the IdP, vlair still has them. Adding OIDC (and SAML 2.0 as a follow-on) is the single highest-leverage enterprise enabler in the backlog.

## What Changes

- New `webapp/auth/sso/` package containing an OIDC client implementation (`authlib` or PyJWT + `requests`) and a pluggable auth-backend interface.
- New endpoints:
  - `GET /api/auth/sso/login?provider=<id>` — kicks off the OIDC redirect.
  - `GET /api/auth/sso/callback?provider=<id>` — handles the auth-code exchange, issues a vlair JWT.
  - `GET /api/auth/sso/providers` — lists configured providers for the SPA login screen.
- New configuration block in `~/.vlair/sso.json` (or env vars) per provider: `client_id`, `client_secret`, `discovery_url`, `scopes`, `group_claim`, `group_role_map`.
- Group-to-role mapping: a YAML mapping resolves IdP group names to vlair `Role` values. Unmapped groups default to `viewer`.
- "Just-in-time" user provisioning: first OIDC login auto-creates a local user row keyed by `iss + sub`. Local password is never set for SSO users.
- Local password auth and TOTP MFA remain available, controlled per-user by `auth_mode = "local" | "sso" | "both"`.
- Off-boarding hook: `POST /api/admin/sso/sync` (or scheduled task) revokes JWTs for users no longer in the IdP's expected group.
- Audit rows distinguish `auth_method` (`password`, `sso:<provider>`, `apikey`).
- **BREAKING**: Webapp config changes — `VLAIR_SSO_PROVIDERS` env var documented; existing deployments unaffected if not set.

## Capabilities

### New Capabilities
- `sso-authentication`: OIDC-based authentication, JIT provisioning, group-to-role mapping, off-boarding sync.

### Modified Capabilities
- `operationalize`: webapp login flow and JWT issuance gain an SSO path; `auth_method` recorded in audit log.

## Non-goals

- SAML 2.0 (deferred to a separate change once the auth-backend abstraction is in place).
- SCIM provisioning (out of scope; off-boarding via group-membership poll is the v1 substitute).
- Per-workspace SSO configuration. v1 is deployment-wide; multi-tenant SSO follows the `multi-tenant-workspaces` change.
- Identity federation across multiple IdPs in a single sign-in flow.
- Replacing the local user table — local accounts still exist, side by side with SSO users.

## Impact

- **Code**: new `webapp/auth/sso/` package, modifications to `webapp/auth/routes.py`, `webapp/auth/decorators.py`, `webapp/auth/models.py` (new columns: `iss`, `sub`, `auth_mode`).
- **Schema**: nullable `iss TEXT`, `sub TEXT`, `auth_mode TEXT DEFAULT 'local'` columns on `users`.
- **Dependency**: `authlib>=1.2` (or `python-jose` for token verification + `requests` for discovery).
- **Tests**: new `tests/test_sso.py` — mocks an OIDC discovery endpoint, exercises the full callback flow, group mapping, and JIT provisioning.
- **Docs**: new `docs/SSO.md` with config recipes for Okta, Auth0, Microsoft Entra ID, and Google Workspace.
- **Deployment**: TLS becomes mandatory for OIDC (callbacks); update `DEPLOYMENT.md`.
