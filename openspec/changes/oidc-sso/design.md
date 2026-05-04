## Context

vlair's auth is monolithic: `webapp/auth/utils.py` issues HMAC-signed JWTs from a local user table; `webapp/auth/routes.py` is the only login surface; `webapp/auth/decorators.py` validates exclusively against the local table. Adding SSO without breaking this requires two things: (1) a clear seam where alternative auth backends can produce a vlair `User` and emit a vlair JWT, and (2) acknowledgement that an SSO user has *no* local password but still needs a stable identifier in our SQLite schema.

The OIDC ecosystem is mature. The smallest viable client uses the discovery document (`/.well-known/openid-configuration`), authorization-code flow with PKCE, and ID-token validation against the JWKS endpoint. `authlib` does all of this in ~30 lines of code; `python-jose` + `requests` works too with more boilerplate. Either is acceptable.

## Goals / Non-Goals

**Goals:**
- A user logs in once via their corporate IdP, lands in the SPA with a working vlair JWT.
- IdP group claim → vlair `Role` mapping is declarative (YAML/JSON), not code.
- Off-boarding: removing a user from the IdP group revokes their access within minutes, not at JWT TTL.
- Local + SSO can coexist. Some users may still be local-only (e.g., emergency break-glass account).
- The auth code stays small and auditable; no monkey-patched OAuth dance.

**Non-Goals:**
- SAML 2.0, SCIM, MFA factor management on the IdP side, password reset flows for local accounts (already exists).
- Replacing or migrating the local user table.
- Multi-IdP federation in a single login.

## Decisions

### D1. Use `authlib` for the OIDC client

`authlib` is the best-maintained Python OIDC library, used by FastAPI/Starlette communities, supports PKCE out of the box, and integrates cleanly with Flask. Pinning to `authlib>=1.2,<2.0`.

**Alternatives considered:** Hand-rolled with `requests` + `python-jose` (rejected: more code, more chances to get token validation subtly wrong). `Flask-OIDC` (rejected: legacy, fewer maintainers, last release 2024).

### D2. Pluggable auth-backend interface

Introduce `webapp/auth/backends/base.py`:

```python
class AuthBackend(ABC):
    @abstractmethod
    def authenticate(self, request) -> Optional[User]: ...
    @abstractmethod
    def initiate_login(self, request) -> Response: ...
```

`LocalPasswordBackend` and `OIDCBackend(provider_name)` implement this. The webapp loads enabled backends from config; the SPA's `/api/auth/sso/providers` returns metadata for each.

**Alternatives considered:** Hard-coded if/else in routes (rejected: doesn't extend to SAML cleanly later).

### D3. JIT user provisioning keyed by `(iss, sub)`

OIDC subjects are stable per issuer but not globally unique. Composite key `(iss, sub)` is the right identity. `users.email` is *not* the join key — emails change, get reused, and aren't claimed in some setups.

On first login: insert a `users` row with `auth_mode='sso'`, `password_hash=NULL`, `iss=<issuer>`, `sub=<subject>`, `email=<email_claim>`. Subsequent logins update `email` and `last_login` only.

**Alternatives considered:** Email as the key (rejected as above). UUID generated locally and mapped via a side table (rejected: adds a join, no benefit).

### D4. Group-to-role mapping is a JSON file, not in the DB

Operators will edit the mapping in version-controlled config. Storing in SQLite would invite drift and complicate disaster recovery.

```json
{
  "okta-prod": {
    "groups": {
      "vlair-admins": "admin",
      "vlair-senior": "senior_analyst",
      "vlair-analysts": "analyst",
      "vlair-readonly": "viewer"
    },
    "default_role": "viewer"
  }
}
```

If no group claim matches, the user gets `default_role`. If no `default_role`, the login is rejected with an audit row.

### D5. Off-boarding via periodic group-membership poll

OIDC ID tokens get re-issued at refresh time. Between refreshes the IdP can have removed the user. Two-pronged solution:

1. **At every access-token refresh**, the OIDC backend re-queries the IdP's userinfo endpoint and re-applies the group → role mapping. If the user is gone or has no mapped group, refresh returns 401 and revokes existing tokens.
2. **Optional scheduled job** (`vlair sso sync`) iterates over active SSO users, polls the IdP, revokes tokens for missing/unauthorized users. Designed to run from a cron / systemd timer.

**Alternatives considered:** Webhook from the IdP (rejected: not all IdPs support push; v1 stays pull-based).

### D6. PKCE always on

Even though we're a confidential client, PKCE adds defense-in-depth and is required by some IdPs. `authlib` handles this transparently.

### D7. State + nonce stored server-side, keyed by a short-TTL cookie

The redirect dance needs CSRF protection (`state`) and replay protection (`nonce`). Store both in a 10-minute SQLite-backed table keyed by a HMAC-signed cookie value. Avoids leaking state via query params and avoids global Redis dependency for first-time deploys.

### D8. TLS is mandatory for OIDC callbacks in production

`Strict-Transport-Security` is already emitted; the SSO callback URL MUST use HTTPS or registration with the IdP fails. `DEPLOYMENT.md` already requires TLS termination — this just makes it non-optional when SSO is on.

## Risks / Trade-offs

- [Risk] Misconfigured group mapping locks all users out. → Mitigation: at least one local admin account is required even when SSO is on; documented as the break-glass account. The `oidc-sso` change refuses to start if the user table has zero local admins and SSO is the only configured backend.
- [Risk] IdP downtime blocks logins. → Mitigation: existing JWTs continue to work for their TTL (default 15 min). Refresh fails until IdP recovers; existing sessions degrade gracefully.
- [Risk] Token validation accepts a forged ID token. → Mitigation: validate `iss`, `aud`, `exp`, `iat`, `nbf`, `nonce`, signature against the JWKS endpoint; refresh JWKS daily and on `kid` miss.
- [Risk] Discovery URL unreachable. → Mitigation: cache the discovery doc and JWKS for 24 hours; surface a clear admin-facing error when refresh fails.
- [Risk] `authlib` major version bump breaks the integration. → Mitigation: pin major version; CI runs the SSO test suite against the pinned version.
- [Trade-off] OIDC adds a 5–10 second latency to first login (discovery + JWKS fetch). Acceptable; cached afterward.

## Migration Plan

1. Land the `AuthBackend` abstraction with the existing local password code refactored behind it. No behavior change; safe to merge.
2. Land `OIDCBackend` and the `/api/auth/sso/*` endpoints behind `VLAIR_SSO_ENABLED=true`. Off by default.
3. Internal validation: configure against Okta dev tenant, walk a real user through login → analyze → logout.
4. Document configuration in `docs/SSO.md` with provider-specific examples.
5. Enable for a beta customer; collect feedback.
6. GA after one customer has run on it for 30 days.

**Rollback:** `VLAIR_SSO_ENABLED=false` disables all SSO routes; local users keep working unchanged.

## Open Questions

- Should the SPA login page show "Continue with <provider>" buttons before or after the username/password form? (Recommendation: providers above the divider, with the divider labeled "or sign in with username".)
- Auto-merge an existing local user with their SSO identity on first match? (Recommendation: no — refuse and require an admin to link explicitly. Auto-merge is a privilege-escalation risk.)
- Refresh token strategy for SSO users: rely on vlair's local refresh token, or always re-validate against the IdP? (Recommendation: vlair refresh token, but with the userinfo + group recheck per D5.)
