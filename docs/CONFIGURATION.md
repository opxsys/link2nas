# Configuration

Link2NAS is configured through environment variables loaded from a `.env` file at startup.

- **`.env`** — private, contains real values. Never commit this file.
- **`.env.sample`** — public template with documented placeholders. Safe to commit.

All variables have defaults unless marked **required**.

---

## App / bootstrap

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `link2nas` | Application name — used as env fallback. Overridable in Admin UI. |
| `APP_TAGLINE` | `Job management + debrid provider` | Short tagline — env fallback, overridable in Admin UI. |
| `APP_VERSION` | `unknown` | Version string shown in system info. Set to the release tag in production (e.g. `vX.Y.Z`). |
| `PUBLIC_BASE_URL` | *(empty)* | Public-facing base URL, no trailing slash. **Required** for email links (magic login, invitations, password reset, email verification). Example: `https://link2nas.example.com` |

---

## Security

| Variable | Default | Description |
|---|---|---|
| `FLASK_SECRET_KEY` | `change-me` | Flask session signing key. **Required** in production — minimum 20 characters, not a placeholder. |
| `V2_SECRET_ENCRYPTION_KEY` | *(empty)* | Fernet encryption key for secrets stored in the database. **Required** in production. |

Generate a valid Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Both variables are rejected at startup (when `DEBUG=false`) if empty, too short, or set to a known placeholder.

**Do not lose `V2_SECRET_ENCRYPTION_KEY`.** Provider, destination, and SMTP credentials are encrypted with this key. Losing it makes stored secrets permanently unreadable.

See [SECURITY.md](SECURITY.md) for the full security model.

---

## Single-user mode

| Variable | Default | Description |
|---|---|---|
| `LINK2NAS_SINGLE_USER_MODE` | `false` | If `true`, enables single-user mode. The registration/login flow is replaced by a fixed auto-created account. |
| `LINK2NAS_SINGLE_USER_EMAIL` | `single-user@link2nas.local` | Email for the single-user account. Used at first startup only — see Bootstrap variables below. |
| `LINK2NAS_SINGLE_USER_DISPLAY_NAME` | `Single User` | Display name for the single-user account. Used at first startup only. |

### What single-user mode does

When `LINK2NAS_SINGLE_USER_MODE=true`:

- The setup wizard is skipped — no "create first admin" step on a fresh database.
- `GET /api/v2/me` is accessible without a token — the single-user account is returned.
- The single-user account is created automatically on startup if absent, using `LINK2NAS_SINGLE_USER_EMAIL` and `LINK2NAS_SINGLE_USER_DISPLAY_NAME`.
- The account is always a **super admin** with email verification pre-confirmed.
- Normal password login is not required — the account may have no password hash (`password_hash=None`).
- The Next UI hides sections irrelevant to a solo installation: Admin Users, Admin Announcements, multi-user email templates (invitation, password reset, email verification, magic login, announcement), most auth rate-limit counters, the Password Policy section, and multi-user TTL security fields.
- Settings > API Keys remains accessible for Prowlarr and qBittorrent integration.
- The session inactivity timeout still applies if configured in Admin > Security.

### What single-user mode does not do

- It does not delete existing users or announcement records from the database.
- It does not run a migration from multi-user to single-user.
- It does not disable multi-user backend endpoints — the UI filters are frontend-only.

### Bootstrap variables

`LINK2NAS_SINGLE_USER_EMAIL` and `LINK2NAS_SINGLE_USER_DISPLAY_NAME` are **bootstrap** variables. They are read only to configure the account on first startup (or when the account is absent from the database). Changing them after the account is created has no effect unless the account is removed from the database.

These variables are not a permanent migration mechanism. Do not rely on them to re-configure an existing installation.

### ⚠ Warning — do not switch modes on an existing database

**Do not switch an existing production database between single-user and multi-user modes unless you know exactly what you are doing. This is not a supported migration path.**

- In single-user mode, the auto-created account may have no password hash. This is intentional: no login is required.
- If you re-enable multi-user mode on the same database, that account may not be usable for classic password login and cannot be used as a multi-user admin without manual remediation.
- To change modes cleanly, start from a fresh database, or perform a controlled manual migration.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the symptom and resolution.

---

## Multi-user mode

Multi-user mode is the default (`LINK2NAS_SINGLE_USER_MODE=false`).

Behaviour:

- On a fresh database, the first visit shows the setup wizard to create a super admin account.
- Login is required — every user authenticates with email + password or magic login.
- `GET /api/v2/me` requires a valid `X-Api-Key` session token.
- The Admin UI shows all sections: Users, Announcements, full email template library, full security TTL fields, all rate-limit counters.
- SMTP is optional but required for invitation, magic login, password reset, and email verification flows.

---

## OIDC / SSO authentication

Link2NAS supports multiple OpenID Connect (OIDC) providers as an optional login method. Providers are configured via **Admin > SSO / OIDC** — not via `.env`. No OIDC credentials are stored in environment variables. The local email + password login always remains available.

**OIDC is not available in single-user mode.** When `LINK2NAS_SINGLE_USER_MODE=true`, the SSO section is hidden in the Admin UI and no OIDC providers are exposed on the login page.

### Prerequisites

- A standard OpenID Connect provider that exposes a discovery document at `{issuer}/.well-known/openid-configuration`.
- A confidential client (client ID + client secret) registered in your provider.
- The callback URL registered in your provider — it includes the provider slug:
  ```
  {PUBLIC_BASE_URL}/api/v2/auth/oidc/{slug}/callback
  ```
  The `{slug}` is the value set in **Admin > SSO / OIDC** when creating the provider.

### Provider configuration (Admin > SSO / OIDC)

| Field | Description |
|---|---|
| Name | Display name for the provider (internal reference). |
| Slug | URL-safe identifier used in auth routes (e.g. `keycloak`). Set at creation — cannot be changed. |
| Enabled | Whether this provider is active and shown on the login page. |
| Issuer | Provider URL. Must expose `{issuer}/.well-known/openid-configuration`. |
| Client ID | Application client ID registered with the provider. |
| Client secret | Application client secret. Encrypted at rest — never returned by API. |
| Scopes | Space-separated OAuth scopes. Must include `openid` and `email`. Default: `openid email profile`. |
| Button label | Label shown on the SSO button on the login page (e.g. "Sign in with Keycloak"). |
| Auto-create users | If enabled, a new Link2NAS account is created on first OIDC login when no matching account exists. Auto-created accounts are always assigned the `user` role. |
| Allowed domains | Restrict auto-creation to specific email domains (comma-separated). Leave empty to allow all domains. Only applies when auto-create is enabled. |
| State TTL (seconds) | Lifetime of the OIDC state parameter. Default: 600. |
| Exchange code TTL (seconds) | Lifetime of the temporary exchange code used in the callback → complete flow. Default: 60. |
| Sort order | Display order among providers on the login page. |

Multiple providers can be configured simultaneously. Each has its own slug and callback URL.

### Security notes

- **`client_secret` is encrypted at rest** using `V2_SECRET_ENCRYPTION_KEY` (Fernet). It is never returned by any API endpoint.
- **`GET /api/v2/public/app-info`** exposes only `slug` and `button_label` per provider — no credentials, no issuer, no client ID.
- **`email_verified` is required.** Tokens without a verified email claim are rejected.
- **No `super_admin` via OIDC.** Auto-created accounts are always assigned `user` role. Role promotion requires manual action in **Admin > Users**.
- **Auto-create is disabled by default.** If disabled, only users with an existing Link2NAS account whose email matches the OIDC `email` claim can sign in via SSO.
- **Session model unchanged.** After OIDC login, Link2NAS issues a standard session token stored in `localStorage` and sent as `X-Api-Key` — identical to local login.
- **No secrets in URLs.** The OAuth authorization code, exchange code, and session token are never placed in URLs.

### Rate limiting

OIDC endpoint rate limits are managed in **Admin > Security > Anti-abuse / Rate limits** (visible in multi-user mode only):

| Counter | Default limit | Window |
|---|---|---|
| OIDC Initiate | 20 requests | 300 s |
| OIDC Callback | 30 requests | 300 s |
| OIDC Complete | 20 requests | 300 s |

These counters are hidden in single-user mode. Default values can be overridden via environment variables if needed (`V2_RATE_LIMIT_OIDC_*` in `config.py`) — they are not documented in `.env.sample`.

---

## Identity Proxy authentication

Link2NAS supports **Identity Proxy** authentication as an optional login method. In this mode, a trusted reverse proxy — such as Cloudflare Access — authenticates the user before the request reaches Link2NAS. The proxy attaches a signed JWT to each request; Link2NAS validates it to identify the user without requiring password input.

### OIDC vs Identity Proxy

| Feature | OIDC | Identity Proxy |
|---|---|---|
| User interaction | Redirect to provider login page | Transparent — proxy handles auth |
| Credential entry | At the OIDC provider | At the proxy (e.g. Cloudflare Access) |
| Token exchange | Authorization Code Flow | JWT in HTTP header (`Cf-Access-Jwt-Assertion`) |
| Login page button | Yes — one per enabled provider | Optional — `auto_login` can bypass the login page |
| Typical use case | External identity providers, SSO | Cloudflare Access, VPN-gated internal access |

**Identity Proxy is not available in single-user mode.** When `LINK2NAS_SINGLE_USER_MODE=true`, the Identity Proxy section is hidden in the Admin UI and all Identity Proxy endpoints return `404`.

### Cloudflare Access — setup

**Step A — Create a Cloudflare Zero Trust application**

1. Log in to the Cloudflare Zero Trust dashboard (`one.dash.cloudflare.com`).
2. Navigate to **Access > Applications** and click **Add an application**.
3. Choose **Self-hosted**.
4. Set the **Application domain** to the domain or subdomain where Link2NAS is accessible — for example, `link2nas.example.com`.
5. Configure an **Access policy** to control which users or groups can reach the application.
6. Save the application.

**Step B — Retrieve the team domain**

Your team domain identifies your Cloudflare Zero Trust account. It is visible in the Zero Trust dashboard under **Settings > Custom Pages** or in the application detail page.

It takes the form `{team-name}.cloudflareaccess.com`. Example: `example.cloudflareaccess.com`.

**Step C — Retrieve the application audience (AUD)**

1. In **Access > Applications**, open the application you created.
2. The **Application Audience (AUD) Tag** is shown in the detail view — copy it. It is a 64-character hex string.

Example (fictitious): `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

### Provider configuration (Admin > Identity Proxy)

Identity Proxy is configured from the Admin UI — not via `.env`. The team domain and audience are stored in the database, encrypted with `V2_SECRET_ENCRYPTION_KEY`.

| Field | Description |
|---|---|
| Enabled | Whether Identity Proxy authentication is active. |
| Button label | Text on the login button when auto-login is disabled (e.g. "Sign in with Cloudflare Access"). |
| Auto-login | If enabled, the login page is bypassed automatically when the proxy provides a valid JWT. |
| Auto-create users | If enabled, a new Link2NAS account is created on first sign-in when no matching account exists. Auto-created accounts are always assigned the `user` role. |
| Allowed email domains | Restrict auto-creation to specific email domains (comma-separated). Leave empty to allow any domain. Only applies when auto-create is enabled. |
| Team domain | Your Cloudflare Zero Trust team domain (e.g. `example.cloudflareaccess.com`). |
| Audience (AUD) | The AUD tag from your Cloudflare Access application. |

Use the **Test** button in the Admin UI to confirm that Link2NAS can reach the Cloudflare JWKS endpoint and that the audience is syntactically valid before enabling the integration.

### User behavior

**Auto-login disabled (default):**
The login page shows a button with the configured label. Clicking it sends `POST /api/v2/auth/identity-proxy/login`. If the reverse proxy has attached a valid JWT, the user is signed in immediately.

**Auto-login enabled:**
The login page attempts authentication automatically on load. If the JWT is valid, the user is signed in transparently. If authentication fails, a manual fallback button is shown.

### Rate limiting

| Counter | Default limit | Window |
|---|---|---|
| Identity Proxy Login | 20 requests | 300 s |

This counter is hidden in single-user mode and visible in **Admin > Security > Anti-abuse / Rate limits** in multi-user mode.

Default values can be overridden via environment variables if needed:

| Variable | Default | Description |
|---|---|---|
| `V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_MAX` | `20` | Max login attempts per window per source. |
| `V2_RATE_LIMIT_IDENTITY_PROXY_LOGIN_WINDOW_SECONDS` | `300` | Window duration in seconds. |

These variables are optional and not required in `.env` unless the defaults need adjustment.

---

## Storage paths

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `./data` | Root directory for persistent application data. |
| `USERDATA_DIR` | `./data/userdata` | Per-user data directory. |
| `TORRENT_DIR` | `./data/torrents` | Temporary storage for uploaded `.torrent` files. |
| `TEMP_DIR` | `./tmp/link2nas` | Temporary files during processing. |
| `LOG_DIR` | `./logs` | Log output directory. |

Use absolute paths in production. The application creates these directories on startup if they do not exist.

---

## Database

| Variable | Default | Description |
|---|---|---|
| `V2_DATABASE_BACKEND` | `sqlite` | Database engine: `sqlite` or `postgres`. |
| `V2_SQLITE_PATH` | `./data/link2nas_v2.sqlite3` | Path to the SQLite database file. |
| `V2_POSTGRES_DSN` | *(empty)* | PostgreSQL connection string. **Required** when `V2_DATABASE_BACKEND=postgres`. Example: `postgresql://link2nas:change_me@127.0.0.1:5432/link2nas_v2` |

The database schema is applied automatically on startup.

---

## Redis and queues

| Variable | Default | Description |
|---|---|---|
| `REDIS_HOST` | `127.0.0.1` | Redis hostname. |
| `REDIS_PORT` | `6379` | Redis port. |
| `REDIS_DB` | `0` | Redis database index. |
| `REDIS_URL` | *(empty)* | Full Redis DSN — takes precedence over `HOST`/`PORT`/`DB` for all RQ workers and the rate limiter if set. Example: `redis://redis:6379/0` or `redis://:password@redis:6379/0`. |
| `RQ_QUEUE_NAME` | `link2nas` | Name of the main RQ job queue. |
| `RQ_LOCAL_DOWNLOAD_QUEUE_NAME` | `link2nas-local-downloads` | Name of the local-download RQ queue. |

`REDIS_URL` is preferred for all RQ workers (`worker.py`, `local_download_worker`, `local_download_queue`) and the rate limiter. `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` remain supported as fallback when `REDIS_URL` is not set.

---

## Rate limiting

| Variable | Default | Description |
|---|---|---|
| `V2_RATE_LIMIT_ENABLED` | `true` | Enable or disable rate limiting globally. |
| `V2_RATE_LIMIT_REDIS_REQUIRED` | `false` | If `true`, the app refuses to start when Redis is unavailable. Recommended in production multi-worker setups. |

**In-process memory** (no Redis): suitable for development or single-process deployments. Rate limit state is not shared across processes.

**Redis-backed**: required when running multiple workers or processes that must share rate limit state.

Per-endpoint limits are defined in `config.py` and have sensible defaults. Override them only if needed.

---

## Web server (Gunicorn)

| Variable | Default | Description |
|---|---|---|
| `WEB_CONCURRENCY` | `1` | Number of gunicorn worker processes for the web service. |

The provided `docker-compose.yml` and `docker-compose.ghcr.yml` launch gunicorn with `-w "${WEB_CONCURRENCY:-1}"`, so this variable directly controls the running worker count. Setting it in `.env` is sufficient — no compose file change is needed.

**Recommended: keep at `1` for small self-hosted instances.** A single web worker does not limit concurrent users. Long-running work (job processing, downloads, scheduling) is handled by the dedicated `worker`, `local-download-worker`, and `scheduler` services — not by the web worker count. Increasing `WEB_CONCURRENCY` increases HTTP concurrency, not job throughput.

Increasing `WEB_CONCURRENCY` beyond `1` is an advanced configuration that must be explicitly validated. Before doing so, ensure all of the following conditions are met:

- `V2_RATE_LIMIT_REDIS_REQUIRED=true` — rate limit state must be shared via Redis across all workers
- A single `scheduler` instance only — the scheduler is not designed for concurrent instances
- Dedicated `worker` and `local-download-worker` services running separately
- Startup and migration behaviour validated with concurrent web processes running simultaneously
- Sufficient PostgreSQL connection pool capacity and Redis capacity for the additional connections
- Monitoring and log aggregation in place to detect issues across workers

---

## Providers

Provider credentials (RealDebrid, AllDebrid API keys) are configured **per user through the Settings UI** — not via environment variables.

Credentials are **encrypted at rest** using `V2_SECRET_ENCRYPTION_KEY`. They are not stored in plaintext.

---

## Destinations

Destinations (local storage, Synology NAS) are configured **per user through the Settings UI**.

- **Links-only:** no destination configuration needed.
- **Local storage:** the application writes files to `USERDATA_DIR`. Ensure the process has write permission.
- **Synology NAS:** credentials are encrypted at rest.

---

## SMTP / email

SMTP configuration (host, port, username, password, TLS mode) is managed through the **Admin UI** (`Admin > SMTP`). It is not set via environment variables.

The SMTP password is encrypted at rest using `V2_SECRET_ENCRYPTION_KEY`.

`PUBLIC_BASE_URL` must be set for outbound email links (magic login, invitation, password reset, email verification) to be correct.

---

## Runtime and admin settings

Several operational settings — including cleanup retention, job orchestration, restart cooldowns, local download worker behavior, and notification dispatcher — are configurable from the **Admin UI** at runtime and stored in the database.

Environment variables serve as the **bootstrap configuration and fallback** for infrastructure-level settings (secrets, paths, database, Redis). Runtime behavior is managed through the Admin interface after the first startup.

---

## Development and debug

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `false` | Enable Flask debug mode. **Do not enable in production.** |
| `V2_DEV_ROUTES_ENABLED` | `false` | Expose additional development routes. Only active when `DEBUG=true`. |
| `HOST` | `0.0.0.0` | Bind address for `python app.py`. |
| `PORT` | `5000` | Port for `python app.py`. |

In production, `HOST` and `PORT` are typically set by the process manager or reverse proxy — not by the application directly.

---

## Security notes

See [SECURITY.md](SECURITY.md) for:
- The full authentication model
- Key rotation warnings
- Deployment hardening recommendations
- Pre-publication checklist
