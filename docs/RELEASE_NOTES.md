# Release Notes

## v3.6.0-beta.1

### Summary

This release adds generic OpenID Connect (OIDC) / SSO authentication as an optional login method. The local email + password login is unchanged. Configuration is via `.env` only — no Admin UI in this version.

---

### Added

**Generic OIDC / SSO authentication**

Link2NAS now supports any standard OpenID Connect provider (Keycloak, Authentik, Authelia, Google Workspace, Azure AD, etc.) via the Authorization Code Flow.

Flow overview:

1. User clicks the SSO button on the login page → redirected to the provider.
2. Provider authenticates the user and redirects back to `/api/v2/auth/oidc/callback`.
3. Backend validates the authorization code, verifies the `id_token` (RS256 / ES256 / RS384 / ES384 / RS512), resolves the user.
4. A short-lived `l2n_oidc_exchange` cookie (HttpOnly, SameSite=Lax, scoped to `/api/v2/auth/oidc/complete`) is set.
5. Frontend calls `POST /api/v2/auth/oidc/complete` — the cookie is exchanged for a standard Link2NAS session token returned as JSON.
6. Session is stored in `localStorage` and sent as `X-Api-Key`, identical to local login.

Security properties:

- **No `api_token` in URLs** at any stage of the flow.
- **`l2n_oidc_exchange` cookie is temporary** — HttpOnly, short-lived (default 60 s), scoped to a single endpoint, deleted immediately on success or failure. It is not a global session cookie.
- **Session model unchanged** — Link2NAS continues to use `X-Api-Key` / `localStorage`, identical to local login. No persistent auth cookie is introduced.
- **`email_verified` is mandatory** — tokens without a verified email claim are rejected.
- **No `super_admin` via OIDC** — auto-created accounts and externally mapped accounts are always assigned the `user` role. Role promotion requires manual action in the Admin UI.
- **`OIDC_AUTO_CREATE_USERS=false` by default** — only users with an existing account whose email matches the OIDC `email` claim can sign in via SSO unless auto-creation is explicitly enabled.
- **OIDC is disabled in single-user mode** — `LINK2NAS_SINGLE_USER_MODE=true` forces `oidc_enabled=false` in the public app-info regardless of `OIDC_ENABLED`.

New environment variables (all optional, safe defaults):

| Variable | Default |
|---|---|
| `OIDC_ENABLED` | `false` |
| `OIDC_ISSUER` | *(empty)* |
| `OIDC_CLIENT_ID` | *(empty)* |
| `OIDC_CLIENT_SECRET` | *(empty)* |
| `OIDC_SCOPES` | `openid email profile` |
| `OIDC_BUTTON_LABEL` | `Sign in with SSO` |
| `OIDC_AUTO_CREATE_USERS` | `false` |
| `OIDC_ALLOWED_DOMAINS` | *(empty)* |
| `OIDC_DEFAULT_ROLE` | `user` |
| `OIDC_STATE_TTL_SECONDS` | `600` |
| `OIDC_EXCHANGE_CODE_TTL_SECONDS` | `60` |
| `V2_RATE_LIMIT_OIDC_INITIATE_MAX` | `20` |
| `V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS` | `300` |
| `V2_RATE_LIMIT_OIDC_CALLBACK_MAX` | `30` |
| `V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS` | `300` |
| `V2_RATE_LIMIT_OIDC_COMPLETE_MAX` | `20` |
| `V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS` | `300` |

Callback URL to register with your provider: `{PUBLIC_BASE_URL}/api/v2/auth/oidc/callback`

**Next UI — SSO login button and callback page**

- Login page: SSO button displayed below the local login form when `oidc_enabled=true` in app-info. Button label is `OIDC_BUTTON_LABEL` (default: "Sign in with SSO"), with i18n support (EN/FR).
- New public route `/oidc/callback`: completes the exchange, stores the session token, redirects to the home page or `/settings` if `force_password_change` is set.
- Local login form and all existing auth flows are unchanged.

**New unit tests**

- `scripts/tests/unit/test_oidc_external_identity_repository.py` — 6 tests: create, get by issuer/subject, get by user ID, duplicate constraint, update last used.
- `scripts/tests/unit/test_oidc_state_repository.py` — 8 tests: create, consumed/expired exclusions, `mark_callback_consumed`, `get_valid_by_exchange_code` requires `user_id NOT NULL`, delete, delete_expired.
- `scripts/tests/unit/test_oidc_service.py` — 14 tests: `handle_callback` (disabled, invalid state, email not verified, disabled/expired user, auto-create off, happy path — no token created); `complete_login` (invalid exchange code, one-time use, user not found, disabled/expired user, happy path — token created and state deleted).
- `scripts/tests/unit/test_oidc_routes.py` — 15 tests: `/initiate` (disabled → 404, success → 302); `/callback` (success, cookie flags, Secure flag, exchange_code not in Location, error redirect cases); `/complete` (no cookie → 400, success → 200 + cookie cleared, exchange error, user error → generic 401).
- `scripts/tests/unit/test_app_info_oidc.py` — 4 tests: OIDC disabled, OIDC enabled with label, OIDC forced off in single-user mode, response key whitelist + no internal values leaked.

---

### Documentation

| File | What changed |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | New `## OIDC / SSO authentication` section: prerequisites, full variable table, rate limit table, security notes. |
| [SECURITY.md](SECURITY.md) | New `### OIDC / SSO authentication` subsection in Authentication: session model, temporary cookie properties, no-secrets-in-URLs guarantee. |
| [`.env.sample`](../.env.sample) | New `── OIDC / SSO authentication` block with all 17 variables documented. |
| [`.env.docker.sample`](../.env.docker.sample) | Same OIDC block. |
| [`.env.docker.postgres.sample`](../.env.docker.postgres.sample) | Same OIDC block. |

---

### Known limitations / Notes

- **No Admin UI for OIDC in v3.6.** All OIDC configuration is done via `.env`. A future release may add an Admin interface for provider configuration, user-identity management, and OIDC-specific audit logs.

- **`OIDC_DEFAULT_ROLE` is locked to `user`.** The configuration key exists for forward compatibility. No other value is accepted in this release.

- **No OIDC-initiated logout (RP-Initiated Logout).** Clicking "Sign out" in Link2NAS revokes the local session token only. The session with the OIDC provider is not terminated. Users must sign out from the provider separately if needed.

- **External identity linking uses issuer + subject as the stable identifier.** On first OIDC login, if no external identity exists yet, Link2NAS can match an existing local user by verified email. After that initial link, issuer + subject is the stable identifier used on all subsequent logins. If the provider changes or the subject changes, the identity will not match automatically and must be relinked manually.

---

## v3.5.0-beta.13

### Summary

This pre-release consolidates security fixes, PostgreSQL compatibility corrections, documentation updates, and a full single-user mode overhaul applied across beta.6 through beta.13. It supersedes all earlier v3.5 betas. Not a stable release.

---

### Added

**Single-user UI simplification**

When `LINK2NAS_SINGLE_USER_MODE=true`, the Next UI now hides sections that are irrelevant to a solo deployment:

- Sidebar: **Announcements** nav item hidden; direct URL navigation redirects to Dashboard.
- Admin nav: **Users** and **Announcements** sections hidden.
- Admin Overview: user metric tiles (Total Users, Active Users) and the User Accounts card hidden. Announcements config row hidden.
- Admin Email Templates: `invitation`, `password_reset`, `email_verification`, `magic_login`, and `announcement` templates hidden. Remaining: `smtp_test`, `notification_event`, `notification_test`.
- Admin Security: Password Policy and Token & Session TTL sections hidden in single-user mode.
- Admin Security / Anti-Abuse: all auth/account-flow rate-limit counters hidden. `qBittorrent Add` counter remains.
- Settings > API Keys: always visible — required for Prowlarr and qBittorrent integration.

Multi-user mode is strictly unchanged.

**PostgreSQL startup delay (`LINK2NAS_STARTUP_DELAY_SECONDS`)**

A configurable startup delay (default: 20 seconds) is applied to the three background services (`worker`, `scheduler`, `local-download-worker`) on PostgreSQL deployments. This gives the `web` service time to complete schema initialization on a fresh `postgres_data` volume before the other services start. Configured via `LINK2NAS_STARTUP_DELAY_SECONDS` in `.env`, applied in `docker-compose.postgres.yml`.

**New unit tests**

- `scripts/tests/unit/test_single_user_mode.py` — `SingleUserService` and setup/status behaviour: fresh DB creates account; reuse by canonical ID or by email; promotion to super_admin; reactivation of a disabled account; idempotence.
- `scripts/tests/unit/test_logout_revokes_session_token.py` — token revocation via `ApiTokenRepository.deactivate()`: active before deactivate, invalid after, idempotent call, other tokens for the same user unaffected, magic-login token treated identically to a session token.

Both are auto-discovered by `bash scripts/quality/check_unit_tests.sh`.

---

### Changed

**`APP_VERSION` now injected from release tag in GHCR image**

The published GHCR image (`ghcr.io/opxsys/link2nas`) now has `APP_VERSION` set at image build time from the GitHub release tag. Users deploying from the GHCR image should **remove** any `APP_VERSION` line from their `.env` — the correct version is already embedded in the image, and a `.env` override would replace it.

For local source builds (`docker-compose.yml`), `APP_VERSION` still defaults to `unknown` unless injected manually via `--build-arg APP_VERSION=...` or set in `.env`.

**Logout now revokes the session token server-side**

`POST /api/v2/auth/logout` now deactivates the current `X-Api-Key` session token in the database. After logout, the same token returns `{"error": "Invalid API key"}` on all authenticated endpoints.

Previously, logout was client-only: the token was removed from `localStorage` but remained valid server-side.

User API Keys created in **Settings > API Keys** are not session tokens and are not affected by logout. Magic login tokens are treated as session tokens and are revoked in the same way.

Logout in single-user mode is a no-op server-side and does not block access.

**`/app/data/torrents` created automatically at startup**

The internal torrent cache directory is now created at startup if absent. No manual `mkdir` is required on fresh installs or Docker volume mounts.

---

### Fixed

**Single-user fresh install**

On a fresh database with `LINK2NAS_SINGLE_USER_MODE=true`:

- `GET /api/v2/setup/status` now returns `{"setup_required": false, "single_user_mode": true}`. Previously it returned `setup_required: true`, which caused the Next UI to display the setup form.
- `GET /api/v2/me` now works without `X-Api-Key` and returns the single-user account.
- The Next UI loads directly without a login or setup screen.
- The single-user account is created automatically on startup. If an account with the configured email already exists, it is reused and promoted to super_admin — no error is raised.

**PostgreSQL: `api_tokens.is_active` boolean comparison**

`api_tokens.is_active` is now stored and queried as a boolean (`false`/`true`) on PostgreSQL. Previously the comparison used an integer literal (`0`), causing token deactivation to silently fail on PostgreSQL: revoked tokens remained active and could still be used.

---

### Documentation / Validation

| File | What changed |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Single-user mode section expanded: full behaviour description, bootstrap variable caveat, mode-switch warning. New Multi-user mode section. |
| [DOCKER.md](DOCKER.md) | New "Choosing a deployment mode" section before First Setup: mode table, switch warning, safe reset instructions. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | New "Single-user mode" section: login failure after single→multi switch, cause, unsupported path warning, recovery options. |
| [testing.md](testing.md) | New unit test coverage entries and run commands. Two new rows in "When to use each runner". Frontend build/type-check commands added to Quick commands. |
| [NON_REGRESSION_CHECKLIST.md](NON_REGRESSION_CHECKLIST.md) | Section H replaced: H1 — 18-point single-user mode checklist; H2 — 14-point multi-user non-regression checklist. |

---

### Known limitations / Notes

- **Single-user ↔ multi-user mode switch is not a supported migration path.** Do not change `LINK2NAS_SINGLE_USER_MODE` on an existing production database. The single-user account may have no password hash and cannot be used for multi-user login. Choose the mode before the first startup. See [CONFIGURATION.md](CONFIGURATION.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

- **PostgreSQL concurrent startup race not fully resolved.** `LINK2NAS_STARTUP_DELAY_SECONDS` reduces the probability of a schema init race on fresh volumes but does not eliminate it. The correct fix (`pg_advisory_xact_lock`) is tracked in [BACKLOG.md](BACKLOG.md).

- **`APP_VERSION` for local source builds.** Local builds still display `unknown` unless `APP_VERSION` is injected via `--build-arg APP_VERSION=...` or set in `.env`. The GHCR image handles this automatically.

---

## V3 / Next UI

### Summary

This release completes the V3 feature set and makes the Next UI the primary and default web interface.

---

### New UI — Next UI (React + Vite + TypeScript)

The Next UI is a fully rebuilt frontend served under `/next`, now the primary interface for Link2NAS. It replaces the previous Vanilla JS interface in the published application.

Key characteristics:

- React + Vite + TypeScript
- Tailwind CSS + shadcn/ui components
- Light theme by default; dark, high-contrast, and colorblind-friendly themes available
- Collapsible sidebar, desktop-first layout with mobile drawer support
- Full internationalisation: English and French
- Accessibility: ARIA labels, keyboard navigation, status badges with icon + text, not color alone

Pages implemented:

- Dashboard
- Jobs (list, detail, actions)
- New Job (magnet, direct link, .torrent file, batch upload)
- Settings (account, providers, destinations, API keys, notifications, Prowlarr)
- Notifications (channels, rules, event timeline)
- Admin (overview, general, users, SMTP, announcements, email templates, security, timeouts, runtime, cleanup, system events, maintenance)
- Prowlarr (embedded tab or fallback new-tab)
- Public token flows: `/invite`, `/verify-email`, `/reset-password`, `/magic-login`

---

### Admin — Announcements

- Global announcements enable/disable (Admin > Announcements).
- Per-announcement read/acknowledge/dismiss tracking.
- User-facing announcement banner with dismiss and acknowledge actions.
- Admin tracking view (opens, reads, acknowledges per announcement).
- Email delivery for announcements: only when SMTP is enabled and user has opted in to application announcement emails.
- Disabling global announcements preserves existing announcement records.

> **"Receive application emails" / "Recevoir les e-mails d'annonces applicatives"** — This user preference controls receipt of admin-sent application announcement emails only (maintenance notices, incidents, updates). It does not affect transactional/authentication emails (invitation, password reset, magic login, email verification). Those are always sent when required.

---

### Notifications

- User notification channels: email, Gotify, webhook.
- Per-user notification rules with severity threshold selection.
- Event timeline visible to users.
- Test notification from Admin > Runtime.
- System notifications visible to super admin.
- Notification dispatcher runtime setting (enabled/disabled from Admin).

---

### Provider / Destination Registry Scaffold

Provider and destination type keys are now centralised in two registry files:

- `backend/services_v2/provider_registry.py` — `PROVIDER_KEYS`, `PROVIDER_DISPLAY_NAMES`, `build_provider()`
- `backend/services_v2/destination_registry.py` — `DESTINATION_KEYS`, `DESTINATION_ALIAS_KEYS`, `DESTINATION_ALL_KEYS`, `DESTINATION_DISPLAY_NAMES`

Frontend type labels and icons are centralised in:

- `frontend-next/src/lib/provider-types.ts`
- `frontend-next/src/lib/destination-types.ts`

Previously, provider and destination type sets were duplicated across 7+ backend files and 4+ frontend components. All of these now import from the registries. See [PROVIDERS_DESTINATIONS.md](PROVIDERS_DESTINATIONS.md) for the developer guide on adding a new provider or destination.

---

### Docker / Infrastructure

- `WEB_CONCURRENCY=1` is the documented and applied default for all Docker deployments.
  - `docker-compose.yml` and `docker-compose.ghcr.yml` launch gunicorn with `-w "${WEB_CONCURRENCY:-1}"`.
  - Setting `WEB_CONCURRENCY` in `.env` is sufficient to change the worker count.
  - A single web worker does not limit concurrent users — job throughput is handled by the dedicated `worker`, `local-download-worker`, and `scheduler` services.
  - Increasing `WEB_CONCURRENCY` beyond `1` is an advanced configuration requiring explicit validation. See [CONFIGURATION.md](CONFIGURATION.md) for prerequisites.
- PostgreSQL fresh install validated with Docker Compose.

---

### Internationalisation

- All visible UI strings in Next UI are translated into English and French.
- Technical identifiers (Real-Debrid, AllDebrid, Synology, Redis, SMTP, Gotify, Webhook, HTTP, URL, API) are not translated.
- Translation keys are type-checked via `TranslationKey` — missing keys produce a compile error.

---

### Documentation added

| File | Content |
|---|---|
| [PROVIDERS_DESTINATIONS.md](PROVIDERS_DESTINATIONS.md) | Developer guide: how to add a provider or destination |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | This file |
| [NON_REGRESSION_CHECKLIST.md](NON_REGRESSION_CHECKLIST.md) | Manual non-regression checklist for pre-release validation |

---

### Compatibility

- The previous Vanilla JS frontend has been removed from the published application; the Next UI is now the supported web interface.
- All `/api/v2/` endpoints are unchanged.
- The Prowlarr / qBittorrent compatibility endpoint is unchanged.
- SQLite and PostgreSQL are both supported and validated.
- The `nas` type alias (`nas` → `synology`) is preserved in all validation paths.

---

### Version management

The application version (`APP_VERSION`) defaults to `"unknown"` and is injected at build/release time — it is not hardcoded in the source.

**GHCR image:** `APP_VERSION` is set automatically from the GitHub release tag at image build time. No `.env` override is needed or recommended.

**Local source build:** `APP_VERSION` defaults to `unknown`. Inject it via `--build-arg APP_VERSION=vX.Y.Z` in the Dockerfile build step, or set it in `.env` as a temporary override.

---

### Migration from legacy UI

No manual data migration is required:

- The app serves the Next UI as the default interface.
- User data, provider profiles, destination profiles, jobs, and settings continue to use the same backend API and database model.
- No manual migration step is required. The application applies its database schema automatically on startup.
