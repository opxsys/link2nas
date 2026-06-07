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

Link2NAS supports generic OpenID Connect (OIDC) as an optional login method alongside the existing email + password flow. Local login always remains available.

**OIDC is disabled by default.** It is configured via `.env` only — there is no Admin UI for OIDC in v3.6.

### Prerequisites

- An OIDC provider that exposes a discovery document at `{OIDC_ISSUER}/.well-known/openid-configuration`.
- An application registered in your provider (client ID + client secret).
- The callback URL registered in your provider:
  ```
  {PUBLIC_BASE_URL}/api/v2/auth/oidc/callback
  ```

### Variables

| Variable | Default | Description |
|---|---|---|
| `OIDC_ENABLED` | `false` | Enable OIDC login. Automatically disabled when `LINK2NAS_SINGLE_USER_MODE=true`. |
| `OIDC_ISSUER` | *(empty)* | Provider discovery URL. Example: `https://idp.example.com` |
| `OIDC_CLIENT_ID` | *(empty)* | Application client ID from your OIDC provider. |
| `OIDC_CLIENT_SECRET` | *(empty)* | Application client secret. Treated as a secret — never logged or exposed. |
| `OIDC_SCOPES` | `openid email profile` | Space-separated scopes. Must include `openid` and `email`. |
| `OIDC_BUTTON_LABEL` | `Sign in with SSO` | Label shown on the SSO button in the login UI. |
| `OIDC_AUTO_CREATE_USERS` | `false` | If `true`, create a Link2NAS account on first OIDC login when no matching account exists. |
| `OIDC_ALLOWED_DOMAINS` | *(empty)* | Comma-separated list of allowed email domains for auto-creation. Empty = all domains allowed. Only applies when `OIDC_AUTO_CREATE_USERS=true`. |
| `OIDC_DEFAULT_ROLE` | `user` | Role assigned to auto-created accounts. Only `user` is accepted — no other role can be assigned via OIDC. |
| `OIDC_STATE_TTL_SECONDS` | `600` | Lifetime of the OIDC state parameter (seconds). |
| `OIDC_EXCHANGE_CODE_TTL_SECONDS` | `60` | Lifetime of the temporary exchange code used in the callback → complete flow (seconds). |

### Rate limiting

| Variable | Default | Description |
|---|---|---|
| `V2_RATE_LIMIT_OIDC_INITIATE_MAX` | `20` | Max `/initiate` requests per window. |
| `V2_RATE_LIMIT_OIDC_INITIATE_WINDOW_SECONDS` | `300` | Rate limit window for `/initiate`. |
| `V2_RATE_LIMIT_OIDC_CALLBACK_MAX` | `30` | Max `/callback` requests per window. |
| `V2_RATE_LIMIT_OIDC_CALLBACK_WINDOW_SECONDS` | `300` | Rate limit window for `/callback`. |
| `V2_RATE_LIMIT_OIDC_COMPLETE_MAX` | `20` | Max `/complete` requests per window. |
| `V2_RATE_LIMIT_OIDC_COMPLETE_WINDOW_SECONDS` | `300` | Rate limit window for `/complete`. |

### Security notes

- **`email_verified` is required.** Tokens without a verified email claim are rejected.
- **No `super_admin` via OIDC.** Auto-created accounts and externally mapped accounts are always assigned `user` role. Role promotion must be done manually in the Admin UI.
- **`OIDC_AUTO_CREATE_USERS=false` by default.** If disabled, only users with an existing Link2NAS account whose email matches the OIDC `email` claim can sign in via SSO.
- **Single-user mode disables OIDC.** When `LINK2NAS_SINGLE_USER_MODE=true`, OIDC is forced off regardless of `OIDC_ENABLED`.
- **Session model unchanged.** After OIDC login, Link2NAS issues a standard session token stored in `localStorage` and sent as `X-Api-Key` — identical to local login. There is no global session cookie. The `l2n_oidc_exchange` cookie is temporary (short-lived, scoped to a single endpoint) and is deleted immediately after the exchange completes.
- **No secrets in URLs.** The OAuth authorization code, exchange code, and session token are never placed in URLs.

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
| `REDIS_URL` | *(empty)* | Full Redis DSN — takes precedence over `HOST`/`PORT`/`DB` for the rate limiter if set. |
| `RQ_QUEUE_NAME` | `link2nas` | Name of the main RQ job queue. |
| `RQ_LOCAL_DOWNLOAD_QUEUE_NAME` | `link2nas-local-downloads` | Name of the local-download RQ queue. |

Both `worker.py` and `local_download_worker` use `REDIS_HOST`/`PORT`/`DB` directly. The rate limiter uses `REDIS_URL` if set, otherwise falls back to the same host/port/db.

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
