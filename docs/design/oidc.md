# Link2NAS — Generic OIDC Authentication Design

Status: planned  
Target version: v3.6.0  
Date: 2026-06-07  
Scope: design only, not implemented yet

## 1. Decision

Link2NAS will target a proper generic OIDC implementation after the definitive v3.5 release.

This is preferred over a Cloudflare-only integration because a generic OIDC flow can support multiple providers through configuration:

- Authentik
- Authelia
- Keycloak
- Azure AD / Entra ID
- Google Workspace
- Cloudflare OIDC
- other standard OIDC providers

Cloudflare Access may still be used immediately as a protective layer in front of Link2NAS, but native Link2NAS authentication should target standard OIDC rather than Cloudflare-specific headers/JWT.

## 2. Current authentication model

Link2NAS currently uses a custom token-based authentication model.

Current flow:

```text
POST /api/v2/auth/login
  -> validate email/password
  -> create opaque Link2NAS api_token
  -> return token to frontend
  -> frontend stores token in localStorage
  -> frontend sends X-Api-Key on API calls
  -> backend validates token in get_user_context()
```

Important existing concepts:

- local login
- logout
- setup first admin
- invitations
- password reset
- magic login
- email verification
- disabled users
- expired accounts
- roles: user, admin, super_admin
- single-user mode
- user API keys
- SQLite and PostgreSQL support
- Next UI frontend

The OIDC implementation must not replace this model initially.

## 3. Core principle

OIDC login must end by creating a normal Link2NAS `api_token`.

The rest of the application should continue to work as it does today:

```text
OIDC provider validates user
  -> Link2NAS validates OIDC response
  -> Link2NAS maps identity to local user
  -> Link2NAS creates normal api_token
  -> frontend continues with X-Api-Key
```

The following parts should remain stable:

- `get_user_context()`
- `require_role()`
- `api_tokens`
- local login
- local fallback access

## 4. Non-goals for the first OIDC version

The first OIDC implementation must not include:

- global migration from `localStorage + X-Api-Key` to browser session cookies
- full HttpOnly session-cookie authentication for the whole app
- removal of local login
- Cloudflare-only JWT/header authentication
- multi-provider UI management
- automatic super_admin provisioning
- disabling local fallback login
- cookie consent banner

A full migration to global HttpOnly session cookies is a separate future security/auth refactor because it requires CSRF handling and broader frontend/backend changes.

## 5. Target architecture

### New backend components

Likely new files:

```text
backend/routes_v2/auth_oidc.py
backend/services_v2/oidc_service.py
backend/models/external_identity.py
backend/repositories/sqlite/external_identity_repository.py
backend/repositories/postgresql/external_identity_repository.py
```

Possible additional files:

```text
backend/services_v2/oidc_state_service.py
backend/models/oidc_exchange_code.py
backend/repositories/sqlite/oidc_exchange_repository.py
backend/repositories/postgresql/oidc_exchange_repository.py
```

### Modified backend files

Likely modified files:

```text
app.py or backend route registration file
config.py
backend/routes_v2/public_app_info.py or equivalent public app-info route
```

### New frontend components

Likely new or modified files:

```text
frontend-next/src/pages/Auth/LoginPage.tsx
frontend-next/src/pages/Auth/LoginForm.tsx
frontend-next/src/pages/Auth/OidcCallbackPage.tsx
frontend-next/src/api/auth.ts
frontend-next/src/api/client.ts only if necessary
frontend-next/src/pages/Auth/auth.types.ts
```

## 6. Required routes

### `GET /api/v2/auth/oidc/initiate`

Starts OIDC authentication.

Responsibilities:

- ensure OIDC is enabled
- reject if single-user mode is enabled
- generate random `state`
- generate random `nonce`
- store `state + nonce` with short TTL
- build authorization URL from provider metadata
- redirect to provider authorization endpoint

### `GET /api/v2/auth/oidc/callback`

Handles provider callback.

Responsibilities:

- validate `state`
- consume `state` one-time
- exchange authorization code for tokens
- validate `id_token`
- validate signature via JWKS
- validate issuer
- validate audience
- validate expiration
- validate nonce
- require `email_verified=true`
- resolve local user
- create Link2NAS `api_token`
- create one-time exchange code
- set short-lived HttpOnly cookie containing only the exchange code
- redirect to frontend callback page

### `POST /api/v2/auth/oidc/complete`

Completes frontend login without exposing the token in the URL.

Responsibilities:

- read HttpOnly exchange cookie
- validate exchange code
- ensure code is not expired
- ensure code is single-use
- consume/delete code
- return normal Link2NAS `api_token` in JSON
- clear exchange cookie

### Optional: `POST /api/v2/auth/oidc/logout`

Not required for the first version.

Initial logout should remain local only:

- revoke local Link2NAS `api_token`
- do not try to log out from the OIDC provider initially

OIDC provider logout may be added later if needed.

## 7. Secure callback design

The final Link2NAS `api_token` must never be returned in the callback URL.

Avoid:

```text
/next?token=l2n_xxxxx
```

Reason:

- token appears in browser history
- token can be logged by reverse proxies
- token can leak through debugging tools
- token can leak through referrer behavior if misconfigured

Preferred flow:

```text
OIDC callback backend
  -> validates provider
  -> creates Link2NAS api_token
  -> creates opaque one-time exchange code
  -> stores exchange_code -> api_token temporarily
  -> sets HttpOnly Secure SameSite=Lax cookie with exchange code only
  -> redirects to /next/oidc/callback
  -> frontend calls /api/v2/auth/oidc/complete
  -> backend consumes exchange code
  -> backend returns api_token in JSON
  -> frontend stores token as today
```

Example cookie:

```text
Set-Cookie: l2n_oidc_exchange=<opaque-one-time-code>;
HttpOnly;
Secure;
SameSite=Lax;
Max-Age=60;
Path=/api/v2/auth/oidc/complete
```

The cookie must contain only the opaque exchange code, not the final `api_token`.

## 8. Database schema

### `external_identities`

Recommended table:

```sql
CREATE TABLE external_identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    linked_at TEXT NOT NULL,
    last_used_at TEXT,
    UNIQUE (issuer, subject)
);
```

Expected indexes:

```sql
CREATE UNIQUE INDEX idx_external_identities_issuer_subject
ON external_identities (issuer, subject);

CREATE INDEX idx_external_identities_user_id
ON external_identities (user_id);
```

PostgreSQL should use equivalent constraints and foreign key cascade if the existing repository/migration style supports it:

```sql
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```

Notes:

- Use `subject` or `sub` consistently. OIDC claim is named `sub`; DB column may be `subject` for clarity.
- `issuer + subject` is the stable external identity key.
- Email is stored for audit and display only, not as the stable external identity key.

## 9. Temporary state, nonce, and exchange-code storage

OIDC needs temporary one-time values:

- `state`
- `nonce`
- `exchange_code`

Options:

### Option A — Database-backed temporary table

Pros:

- works in SQLite and PostgreSQL
- no Redis requirement
- consistent with Link2NAS persistence model
- easy to test
- compatible with Docker single-node deployments

Cons:

- requires cleanup of expired rows
- slightly more DB schema

### Option B — Redis

Pros:

- natural TTL
- simple expiration
- good for production

Cons:

- Redis is optional in some deployments
- not ideal as the only implementation

### Option C — Flask signed session

Pros:

- simple
- no DB table

Cons:

- less consistent with current token model
- can be awkward with frontend/backend routing and proxies
- less explicit/auditable

Recommendation for Link2NAS:

Use a database-backed store for phase 1, with optional Redis optimization later if needed.

Possible table:

```sql
CREATE TABLE oidc_exchange_states (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    nonce TEXT NOT NULL,
    exchange_code TEXT,
    api_token_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
```

Alternative: use separate tables for `oidc_states` and `oidc_exchange_codes` if cleaner.

TTL recommendations:

```text
OIDC_STATE_TTL_SECONDS=600
OIDC_EXCHANGE_CODE_TTL_SECONDS=60
```

## 10. User mapping logic

Resolution order:

### Step 1 — Existing external identity

Search:

```text
external_identities WHERE issuer = id_token.iss AND subject = id_token.sub
```

If found:

- load linked user
- reject if user is disabled
- reject if account is expired
- keep local role unchanged
- update `last_used_at`
- create `api_token`

### Step 2 — Existing local user by verified email

If no external identity exists:

- require `email_verified=true`
- search local user by email case-insensitively

If found:

- reject if user is disabled
- reject if account is expired
- create `external_identities` link
- keep local role unchanged
- create `api_token`

### Step 3 — Unknown email

If user does not exist:

- if `OIDC_AUTO_CREATE_USERS=false`, reject
- if `OIDC_AUTO_CREATE_USERS=true`, validate allowed domain rules
- create local user with role `user` by default
- mark email as verified if the local model supports it
- create `external_identities` link
- create `api_token`

### Required restrictions

- OIDC must never auto-create `super_admin`
- OIDC must not change a user role automatically
- OIDC must not reactivate disabled accounts
- OIDC must not bypass account expiration
- Local roles remain the source of truth
- `issuer + subject` remains the stable identity key even if the email changes later

## 11. Configuration

Phase 1 should use `.env` only.

Recommended variables:

```env
OIDC_ENABLED=false
OIDC_ISSUER=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_SCOPES=openid email profile
OIDC_BUTTON_LABEL=Se connecter avec SSO
OIDC_AUTO_CREATE_USERS=false
OIDC_ALLOWED_DOMAINS=
OIDC_DEFAULT_ROLE=user
OIDC_STATE_TTL_SECONDS=600
OIDC_EXCHANGE_CODE_TTL_SECONDS=60
```

Rules:

- `OIDC_DEFAULT_ROLE` must not allow `super_admin`
- if `OIDC_CLIENT_SECRET` is stored in DB later, it must be encrypted with the existing secret encryption mechanism
- if configured through `.env`, no additional encryption is required beyond file-system protection

## 12. Public app-info impact

The public app-info endpoint should expose only safe values:

```json
{
  "oidc_enabled": true,
  "oidc_label": "Se connecter avec SSO"
}
```

Do not expose:

- issuer if unnecessary
- client_id if unnecessary
- client_secret
- allowed domains
- internal security config

If single-user mode is enabled, app-info should return:

```json
{
  "oidc_enabled": false
}
```

## 13. Frontend Next UI impact

Login page:

- show SSO button only when `oidc_enabled=true`
- button label from `oidc_label`
- clicking button redirects browser to `/api/v2/auth/oidc/initiate`
- local login remains visible

Callback page:

- route such as `/next/oidc/callback`
- on mount, call `/api/v2/auth/oidc/complete`
- if successful, store returned Link2NAS token as current login does
- redirect to the configured home page or `/next`
- if failed, redirect to login with clear error

Error handling:

- OIDC disabled
- invalid or expired state
- provider error
- email not verified
- user not found and auto-create disabled
- domain not allowed
- user disabled
- account expired
- exchange code expired

i18n:

- add French and English labels/messages
- keep wording neutral/professional

## 14. Security requirements

Mandatory:

- random `state`
- random `nonce`
- one-time state consumption
- short TTL for state
- short TTL for exchange code
- validate id_token signature via JWKS
- validate issuer
- validate audience
- validate expiration
- validate nonce
- require `email_verified=true`
- reject disabled users
- reject expired accounts
- never auto-create super_admin
- do not log OAuth codes
- do not log id_token
- do not log access_token
- do not log api_token
- do not log exchange code
- do not log client_secret
- rate-limit OIDC endpoints
- OIDC disabled in single-user mode
- local login remains available as fallback

Cookie requirements for exchange cookie:

```text
HttpOnly
Secure in production
SameSite=Lax
short Max-Age
restricted Path
contains only opaque exchange code
cleared after completion
```

Cookie notice:

- no cookie consent banner is needed for strictly necessary authentication/session cookies
- document the technical cookie in privacy/docs only
- do not add tracking, analytics, advertising, or third-party cookies

## 15. Cloudflare strategy

Do not implement Cloudflare-specific header/JWT authentication first.

If generic OIDC exists, Cloudflare can be used through OIDC configuration without dedicated Cloudflare code.

Recommended strategy:

```text
Short term:
  Cloudflare Access can protect Link2NAS externally, with local login kept.

Medium term:
  Link2NAS v3.6 implements generic OIDC.

After that:
  Cloudflare can be configured as an OIDC provider without Cloudflare-specific code.
```

## 16. Testing strategy

Backend unit tests:

- valid state/nonce generation
- expired state rejected
- replayed state rejected
- invalid nonce rejected
- invalid issuer rejected
- invalid audience rejected
- expired id_token rejected
- missing email rejected
- `email_verified=false` rejected
- unknown user rejected when auto-create disabled
- unknown user created when auto-create enabled
- disabled user rejected
- expired account rejected
- existing email linked to external identity
- existing external identity reused
- role is never changed by OIDC
- super_admin cannot be auto-created
- exchange code is one-time
- expired exchange code rejected

Integration tests:

- full `/initiate` flow with mocked provider metadata
- full `/callback` flow with mocked token endpoint and JWKS
- `/complete` returns token only with valid cookie/code
- `/complete` clears/consumes code
- local login still works
- logout still works
- single-user mode disables OIDC

Database tests:

- SQLite migration
- PostgreSQL migration
- unique `(issuer, subject)` constraint
- cascade delete behavior if implemented

Frontend tests:

- SSO button shown when enabled
- SSO button hidden when disabled
- SSO button hidden in single-user mode
- callback success stores token
- callback error redirects to login/error state

Security checks:

- no token in callback URL
- no sensitive value in logs
- exchange cookie has secure attributes

## 17. Implementation phases

### Phase 0 — Final design

- validate this design
- choose Python libraries
- decide DB schema
- decide state/exchange storage
- decide exact routes and frontend callback path

### Phase 1 — Backend minimal OIDC

- config variables
- provider discovery
- JWKS validation
- state/nonce storage
- callback validation
- external identity repository
- create Link2NAS api_token
- exchange cookie/code
- `/complete` endpoint
- backend tests

### Phase 2 — Frontend minimal

- app-info `oidc_enabled`
- SSO button
- callback page
- error handling
- i18n

### Phase 3 — Hardening and tests

- SQLite tests
- PostgreSQL tests
- provider mock
- replay tests
- security tests
- logging review

### Phase 4 — Documentation

- OIDC configuration guide
- provider examples
- privacy note about technical cookies
- troubleshooting section

### Phase 5 — Optional admin UI

- configure OIDC from Admin UI
- encrypted secret storage
- view linked external identities
- unlink identity
- audit events

Admin UI should not be part of the initial minimal OIDC implementation unless the rest is already stable.

## 18. Estimated complexity

Realistic estimate:

```text
Prototype functional: 1-2 days
Clean minimal implementation: 4-6 days
With tests, docs, SQLite/PostgreSQL validation: 1-2 weeks
```

Complexity:

```text
Development: medium
Security sensitivity: high
Regression risk: moderate if isolated
```

Expected file count:

```text
New files: about 8-12
Modified files: about 5-8
Tests: about 15-25
```

## 19. Risks and mitigations

### Risk: broken local login

Mitigation:

- keep local auth code mostly untouched
- implement OIDC in separate blueprint/service
- test local login after OIDC changes

### Risk: token leak in URL

Mitigation:

- never return api_token in URL
- use exchange cookie/code flow

### Risk: OIDC validation flaw

Mitigation:

- use maintained libraries
- validate issuer/audience/nonce/expiration/signature
- add negative tests

### Risk: unwanted account creation

Mitigation:

- auto-create disabled by default
- allowed domains optional but required in serious deployments
- default role user only

### Risk: super_admin compromise by email matching

Mitigation:

- require email_verified
- never change local roles from OIDC
- local disabled/expired checks still apply

### Risk: single-user mode ambiguity

Mitigation:

- OIDC disabled in single-user mode
- app-info hides SSO
- endpoints return clear error

## 20. Conclusion

Generic OIDC authentication is the right long-term direction for Link2NAS.

It should be implemented after the definitive v3.5 release as a dedicated v3.6 feature branch/release.

Recommended versioning:

```text
v3.5.0 = definitive stabilization release
v3.6.0 = Generic OIDC Authentication
v3.6.x = OIDC provider compatibility fixes
```

Recommended branch:

```text
feature/v3.6-oidc
```

Final decision:

```text
Do not implement OIDC in v3.5 stabilization.
Prepare design and branch now if useful.
Implement OIDC as a dedicated v3.6 feature.
Keep the current X-Api-Key/localStorage model initially.
Use HttpOnly Secure SameSite=Lax only for the temporary OIDC exchange cookie/code.
Do not add a cookie consent banner for strictly necessary technical cookies.
Document the technical cookie in privacy/docs.
```

