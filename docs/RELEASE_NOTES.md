# Release Notes

## v3.6.0-beta.2

### Summary

This beta fixes Docker startup ordering for fresh deployments, especially PostgreSQL installs using the published Compose files.

### Fixed

- Applied `LINK2NAS_STARTUP_DELAY_SECONDS` to background services in `docker-compose.yml` and `docker-compose.ghcr.yml`, in addition to `docker-compose.postgres.yml`.
- This gives the `web` container time to initialize the database schema before `worker`, `scheduler`, and `local-download-worker` start on fresh installs.
- Keeps the default delay at 20 seconds and allows setting `LINK2NAS_STARTUP_DELAY_SECONDS=0` to disable it.

### Validation

- Fresh PostgreSQL + Redis Docker deployment validated with `ghcr.io/opxsys/link2nas:v3.6.0-beta.2`.
- `web`, `worker`, `scheduler`, `local-download-worker`, `postgres`, and `redis` start cleanly.
- `/health` returns `{"ok": true}`.
- No Redis connection errors, PostgreSQL schema race errors, or worker startup errors observed in logs.

---

## v3.6.0-beta.1

### Summary

This release adds generic OpenID Connect (OIDC) / SSO authentication as an optional login method, with full multi-provider support and an Admin UI for provider management. The local email + password login is unchanged. Providers are configured from **Admin > SSO / OIDC** — no OIDC credentials in `.env`.

---

### Added

**Generic OIDC / SSO authentication — multi-provider**

Link2NAS now supports any number of standard OpenID Connect providers (Keycloak, Authentik, Authelia, Google Workspace, Azure AD, etc.) via the Authorization Code Flow. Providers are managed from **Admin > SSO / OIDC** and stored in the database.

Flow overview:

1. User clicks an SSO button on the login page → redirected to the corresponding provider.
2. Provider authenticates the user and redirects back to `GET /api/v2/auth/oidc/{slug}/callback`.
3. Backend validates the authorization code, verifies the `id_token` (RS256 / ES256 / RS384 / ES384 / RS512), resolves the user.
4. A short-lived `l2n_oidc_exchange` cookie (HttpOnly, SameSite=Lax, scoped to `/api/v2/auth/oidc/complete`) is set.
5. Frontend calls `POST /api/v2/auth/oidc/complete` — the cookie is exchanged for a standard Link2NAS session token returned as JSON.
6. Session is stored in `localStorage` and sent as `X-Api-Key`, identical to local login.

Security properties:

- **No `api_token` in URLs** at any stage of the flow.
- **`l2n_oidc_exchange` cookie is temporary** — HttpOnly, short-lived (default 60 s per provider), scoped to a single endpoint, deleted immediately on success or failure. Not a global session cookie.
- **Session model unchanged** — Link2NAS continues to use `X-Api-Key` / `localStorage`. No persistent auth cookie is introduced.
- **`email_verified` is mandatory** — tokens without a verified email claim are rejected.
- **No `super_admin` via OIDC** — auto-created accounts and externally mapped accounts are always assigned the `user` role. Role promotion requires manual action in the Admin UI.
- **Auto-create disabled by default** — only users with an existing account whose email matches the OIDC `email` claim can sign in via SSO unless auto-creation is explicitly enabled.
- **OIDC is disabled and hidden in single-user mode** — when `LINK2NAS_SINGLE_USER_MODE=true`, Admin > SSO / OIDC is hidden, and no OIDC providers are exposed on the login page.
- **`client_secret` encrypted at rest** — provider secrets are encrypted with `V2_SECRET_ENCRYPTION_KEY` (Fernet). Never returned by API. No OIDC credentials in `.env`.

Callback URL to register with your provider (per-provider slug):
```
{PUBLIC_BASE_URL}/api/v2/auth/oidc/{slug}/callback
```

**Admin > SSO / OIDC**

New admin section for managing OIDC providers:
- Shows provider-side configuration references directly in the Admin UI, including the exact OIDC redirect URI / callback URL to register with the provider.
- Create, edit, delete providers.
- Enable / disable individual providers.
- Test discovery endpoint (`POST /api/v2/admin/oidc-providers/{id}/test-discovery`).
- Slug is set at creation and cannot be changed.

New admin API endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v2/admin/oidc-providers/` | List all providers |
| `POST` | `/api/v2/admin/oidc-providers/` | Create a provider |
| `GET` | `/api/v2/admin/oidc-providers/{id}` | Get a provider |
| `PATCH` | `/api/v2/admin/oidc-providers/{id}` | Update a provider |
| `DELETE` | `/api/v2/admin/oidc-providers/{id}` | Delete a provider |
| `POST` | `/api/v2/admin/oidc-providers/{id}/test-discovery` | Test discovery URL |

Public auth routes (slug-aware):

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v2/auth/oidc/{slug}/initiate` | Start OIDC flow for provider |
| `GET` | `/api/v2/auth/oidc/{slug}/callback` | Provider callback |
| `POST` | `/api/v2/auth/oidc/complete` | Exchange cookie for session token |

**Next UI — multi-provider SSO login and callback page**

- Login page: one SSO button per enabled provider, ordered by `sort_order`. Button label is the provider's `button_label`.
- New public route `/oidc/callback`: completes the exchange, stores the session token, redirects to the home page or `/settings` if `force_password_change` is set.
- Local login form and all existing auth flows are unchanged.

**OIDC rate limits in Admin > Security > Anti-abuse**

Three OIDC counters are now visible in **Admin > Security > Anti-abuse / Rate limits** (multi-user mode only):

- OIDC Initiate — default: 20 req / 300 s
- OIDC Callback — default: 30 req / 300 s
- OIDC Complete — default: 20 req / 300 s

These counters are hidden in single-user mode. Defaults can be overridden via `V2_RATE_LIMIT_OIDC_*` environment variables if needed.

**New unit tests**

- `scripts/tests/unit/test_oidc_external_identity_repository.py` — 6 tests: create, get by issuer/subject, get by user ID, duplicate constraint, update last used.
- `scripts/tests/unit/test_oidc_state_repository.py` — 11 tests: create, consumed/expired exclusions, `mark_callback_consumed`, `get_valid_by_exchange_code` requires `user_id NOT NULL`, delete, delete_expired.
- `scripts/tests/unit/test_oidc_provider_repository.py` — repository CRUD.
- `scripts/tests/unit/test_oidc_provider_service.py` — provider service: create/update/delete, secret handling, slug validation, in-use constraint.
- `scripts/tests/unit/test_oidc_service.py` — 21 tests: `handle_callback` (disabled, invalid state, email not verified, disabled/expired user, auto-create off, happy path); `complete_login` (invalid exchange code, one-time use, user not found, disabled/expired user, happy path — token created and state deleted).
- `scripts/tests/unit/test_oidc_routes.py` — 20 tests: slug-aware `/initiate`, `/callback`, `/complete`; cookie flags; Secure flag; error cases; generic error messages.
- `scripts/tests/unit/test_admin_oidc_provider_routes.py` — 16 tests: admin CRUD routes; auth (super admin only); no secret leakage; discovery test; 409 on delete in-use.
- `scripts/tests/unit/test_app_info_oidc.py` — 7 tests: OIDC providers list; no sensitive fields in public response; single-user mode hides providers.
- `scripts/tests/unit/test_anti_abuse_oidc.py` — 7 tests: OIDC kinds in registry; `single_user_hidden=True`; multi-user → kinds visible; single-user → kinds absent; reset kind.

**Identity Proxy authentication — Cloudflare Access**

Link2NAS now supports Identity Proxy authentication as a second optional login method alongside OIDC. A trusted reverse proxy (Cloudflare Access) authenticates the user and attaches a signed JWT in `Cf-Access-Jwt-Assertion`; Link2NAS validates it without requiring user interaction on the login page.

Key properties:

- **Cloudflare Access** (`cloudflare_access`) is the only Identity Proxy provider supported and validated in this release. JWT validated via JWKS at `https://{team_domain}/cdn-cgi/access/certs` — no shared secret stored in Link2NAS. The provider-type architecture is intentionally extensible for future providers.
- **Admin UI:** configured from **Admin > Identity Proxy**. Fields: enabled, button label, auto-login, auto-create users, allowed email domains, team domain, audience (AUD). No Identity Proxy credentials in `.env`.
- **Manual login button:** when auto-login is disabled, the login page shows a button. Clicking it calls `POST /api/v2/auth/identity-proxy/login`.
- **Auto-login:** when enabled, the login page attempts authentication automatically on load. A manual fallback button is shown on failure.
- **Session model unchanged:** after a successful Identity Proxy login, Link2NAS issues a standard `X-Api-Key` session token — identical to local login.
- **`GET /api/v2/public/app-info`** exposes `identity_proxy_enabled`, `identity_proxy_label`, `identity_proxy_auto_login`, `identity_proxy_provider_type` — no `team_domain`, no `audience`.
- **Rate limit:** `identity_proxy_login` counter — default 20 requests / 300 s. Hidden in single-user mode. Overridable via `V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX` and `V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS`.
- **Single-user mode:** Identity Proxy is disabled when `LINK2NAS_SINGLE_USER_MODE=true`. Admin section hidden; all Identity Proxy endpoints return `404`.
- **Auto-create:** auto-created accounts are always assigned the `user` role. No `super_admin` can be created via Identity Proxy.

New admin API endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v2/admin/identity-proxy/config` | Get current Identity Proxy configuration |
| `PATCH` | `/api/v2/admin/identity-proxy/config` | Create or update Identity Proxy configuration |
| `POST` | `/api/v2/admin/identity-proxy/test` | Test JWKS reachability and audience validity |

New public auth endpoint:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v2/auth/identity-proxy/login` | Authenticate via Identity Proxy JWT header |

**Next UI — Admin > Identity Proxy and login page integration**

- New admin section **Admin > Identity Proxy**: form with all configuration fields, test button.
- Login page: shows Identity Proxy button when `identity_proxy_enabled` and auto-login is off.
- Login page: renders `IdentityProxyAutoLogin` component when `identity_proxy_auto_login` is on — attempts login on mount, shows fallback button on failure.
- Admin > Security > Anti-abuse: `identity_proxy_login` counter added; hidden in single-user mode.

---

### Documentation

| File | What changed |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | OIDC section rewritten: multi-provider, Admin UI, per-provider fields, rate limits in Admin Security. `.env` credentials removed. New **Identity Proxy authentication** section: concept, OIDC vs Identity Proxy comparison, Cloudflare Access setup (steps A/B/C), admin config fields, user behavior, rate limits. |
| [SECURITY.md](SECURITY.md) | OIDC subsection updated: multi-provider, encrypted secrets, callback URL with slug, state binding, security invariants. New **Identity Proxy authentication** subsection: JWT validation, JWKS, no JWT logged, session model, proxy trust, auto-create, single-user mode. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | New **Identity Proxy / Cloudflare Access** section: 6 cases — 403 from Cloudflare, 401 Authentication failed (5 sub-causes), test OK but login fails, curl 403 expected behavior, auto-login loop, log security check. |
| [`.env.sample`](../.env.sample) | Identity Proxy rate limit variables added as optional commented overrides. |
| [`.env.docker.sample`](../.env.docker.sample) | Same. |
| [`.env.docker.postgres.sample`](../.env.docker.postgres.sample) | Same. |

---

### Technical improvements

- **OIDC and Identity Proxy are mutually exclusive at activation time.** Both configurations can coexist in the database, but only one external authentication family can be enabled at a time. Admin routes now enforce this: enabling Identity Proxy is rejected if any OIDC provider is active, and enabling an OIDC provider is rejected if Identity Proxy is active. Disabling the active mode before enabling the other is the intended flow. Multiple OIDC providers may be enabled together. Local login is always available regardless.

- **REDIS_URL support for RQ workers and local download queues.** `worker.py`, `local_download_worker.py`, and `local_download_queue.py` now prefer `REDIS_URL` for Redis connections, with fallback to `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB`. A shared helper `backend/services_v2/redis_connection.py` (`build_redis_connection`) centralises this logic. This aligns Docker deployments with the rest of the application configuration.

---

### Known limitations / Notes

- **No OIDC-initiated logout (RP-Initiated Logout).** Clicking "Sign out" in Link2NAS revokes the local session token only. The session with the OIDC provider is not terminated. Users must sign out from the provider separately if needed.

- **External identity linking uses issuer + subject as the stable identifier.** On first OIDC login, if no external identity exists, Link2NAS can match an existing local user by verified email. After that initial link, issuer + subject is the stable identifier. If the provider changes or the subject changes, the identity will not match automatically and must be relinked manually.

- **HTTPS / reverse proxy not covered in this release.** Running behind HTTPS is required for the `Secure` cookie flag to be set correctly. TLS termination via a reverse proxy (nginx, Caddy, Traefik) or Cloudflare is a deployment concern that is not covered in this release.

---

## v3.5.0-beta.15

### Summary

UI/UX stabilisation and provider improvements. No backend business-logic changes.

---

### Fixed

- **Settings — announcement email preference**: the "Receive application emails" option is now hidden in single-user mode, when announcements are globally disabled, or when email sending is unavailable. Previously it appeared in all three cases regardless of relevance.

- **Notifications — SMTP/Email channel availability**: after saving SMTP settings in Admin, the Email notification channel now appears in the channel creation modal without a full browser reload. The `useMe` cache is now invalidated alongside `useSmtpStatus` after a successful SMTP save.

- **Prowlarr page — redundant helper text removed**: the descriptor "Browse and submit via your Prowlarr instance. Configure the integration in Settings → Prowlarr." has been removed from the Prowlarr page header. The text was always visible and was redundant with the empty-state card that already links to Settings.

- **Providers — account expiration display (RealDebrid / AllDebrid)**:
  - The provider row now calls `onReload` after a successful connection test so the expiration date saved to the database appears immediately without a manual page refresh.
  - Unix second timestamps (e.g. `1781973241`) returned by the provider API are now parsed correctly. Previously `new Date("1781973241")` produced `Invalid Date`.
  - Expiration status is shown with a colour-coded badge: expired (red), ≤ 7 days (red/orange "Expires soon"), ≤ 30 days (orange "Expires soon"), > 30 days (neutral), not yet tested (no badge).

---

### Tests

- **`scripts/tests/unit/test_notification_rule_channel_change.py`** — four unit tests covering the notification rule channel-change scenario: event uses initial config; event uses new config after rule update; updated `config_id` persisted in DB; disabled config excluded from rule matching. All four pass.

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

A configurable startup delay (default: 20 seconds) is applied to the three background services (`worker`, `scheduler`, `local-download-worker`) on PostgreSQL deployments. This gives the `web` service time to complete schema initialization on a fresh `postgres_data` volume before the other services start. Configured via `LINK2NAS_STARTUP_DELAY_SECONDS` in `.env`. It was originally applied in `docker-compose.postgres.yml`; v3.6.0-beta.2 extends the same delay to `docker-compose.yml` and `docker-compose.ghcr.yml`.

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
