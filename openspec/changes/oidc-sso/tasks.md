## 1. Auth backend abstraction

- [ ] 1.1 Create `webapp/auth/backends/base.py` with the `AuthBackend` ABC
- [ ] 1.2 Refactor existing local password auth into `LocalPasswordBackend`
- [ ] 1.3 Update `webapp/auth/routes.py` to dispatch through the backend registry
- [ ] 1.4 Tests: existing auth flow unchanged after refactor (regression)

## 2. Schema changes

- [ ] 2.1 Add `iss TEXT`, `sub TEXT`, `auth_mode TEXT DEFAULT 'local'` columns to `users`; add unique index on `(iss, sub)`
- [ ] 2.2 Create `sso_sessions` table for state/nonce/code_verifier (10-minute TTL)
- [ ] 2.3 Migration runs as part of `init_db()`
- [ ] 2.4 Tests: existing user rows get `auth_mode='local'`; SSO columns nullable

## 3. Configuration loader

- [ ] 3.1 New `webapp/auth/sso/config.py` loads provider configs from env vars or `~/.vlair/sso.json`
- [ ] 3.2 Group → role mapping loader with validation (rejects unknown roles)
- [ ] 3.3 Startup guard: refuse to start in production with HTTP callback or no break-glass admin
- [ ] 3.4 Tests: malformed config rejected with clear error; missing required field reported

## 4. OIDC client

- [ ] 4.1 Add `authlib>=1.2,<2.0` to `[ai]` and `[all]` optional deps; new `[sso]` extra
- [ ] 4.2 Implement `OIDCBackend` with discovery caching (24h TTL) and JWKS caching
- [ ] 4.3 Implement `initiate_login` → 302 with state/nonce/PKCE
- [ ] 4.4 Implement `handle_callback` → token exchange, ID-token validation, user resolution
- [ ] 4.5 Implement userinfo re-validation hook used at refresh time
- [ ] 4.6 Tests: mock IdP via responses/httpx_mock; cover happy path, invalid signature, expired token, replay, state mismatch

## 5. SSO routes

- [ ] 5.1 `GET /api/auth/sso/providers` returns configured providers
- [ ] 5.2 `GET /api/auth/sso/login?provider=...` initiates the flow
- [ ] 5.3 `GET /api/auth/sso/callback?provider=...` handles the callback
- [ ] 5.4 `POST /api/admin/sso/sync` admin-only off-boarding sync
- [ ] 5.5 Tests: full HTTP-level coverage of all endpoints

## 6. JIT provisioning + group mapping

- [ ] 6.1 First-login user creation with `(iss, sub)` lookup
- [ ] 6.2 Group → role resolution with `default_role` fallback
- [ ] 6.3 Reject login with no role match and no default
- [ ] 6.4 Tests: provision-on-first, update-on-subsequent, multi-group highest-privilege, no-match-no-default rejection

## 7. Off-boarding

- [ ] 7.1 Refresh-time userinfo + group recheck; 401 + token revocation on miss
- [ ] 7.2 `vlair sso sync` CLI subcommand wrapping the admin endpoint
- [ ] 7.3 Tests: group removed → next refresh fails; sync revokes the right tokens

## 8. Audit log + auth-method tagging

- [ ] 8.1 Add `auth_method` to audit row writer signature
- [ ] 8.2 Update existing call sites (`password`, `apikey`)
- [ ] 8.3 SSO callback writes `auth_method='sso:<provider>'`
- [ ] 8.4 Tests: audit grep returns expected `auth_method` values per flow

## 9. SPA changes

- [ ] 9.1 Sign-in screen fetches `/api/auth/sso/providers` on load
- [ ] 9.2 Renders provider buttons above the local form with a divider
- [ ] 9.3 Callback page handles success / error state, stores tokens, redirects
- [ ] 9.4 Manual UI verification against a real Okta dev tenant

## 10. Documentation

- [ ] 10.1 New `docs/SSO.md` with config recipes for Okta, Auth0, Microsoft Entra ID, Google Workspace
- [ ] 10.2 Update `docs/DEPLOYMENT.md` with SSO section: TLS, callback URL, break-glass account
- [ ] 10.3 Update `docs/INDEX.md` to mention SSO support
