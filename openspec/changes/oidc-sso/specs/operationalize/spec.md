## ADDED Requirements

### Requirement: Audit log records auth method

Every audit row written for an authenticated request SHALL include the authentication method used: `password`, `sso:<provider>`, or `apikey`.

#### Scenario: SSO login audit
- **WHEN** a user logs in via OIDC against the `okta-prod` provider
- **THEN** the audit row's `detail` (or a dedicated `auth_method` column) contains `sso:okta-prod`

#### Scenario: Password login audit
- **WHEN** a user logs in via local password
- **THEN** the audit row's `auth_method` is `password`

### Requirement: SPA sign-in screen surfaces SSO buttons

The webapp SPA SHALL fetch `/api/auth/sso/providers` on the sign-in screen and SHALL render a button per provider above the local username/password form.

#### Scenario: One provider configured
- **WHEN** the SPA loads the sign-in screen and one OIDC provider is configured
- **THEN** the page shows a single "Continue with <provider>" button followed by an "or sign in with username" divider and the local password form

#### Scenario: No providers configured
- **WHEN** the SPA loads and no SSO providers are configured
- **THEN** the page renders only the local username/password form, with no SSO section
