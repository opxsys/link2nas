# Security

Link2NAS is a self-hosted application. The operator is responsible for the security of their deployment: network exposure, access control, secrets management, and system hardening are outside the scope of the application itself.

This document describes the current security model, known trade-offs, and deployment recommendations.

---

## 1. Security model

Link2NAS is designed to be self-hosted, preferably on a **trusted private network** or behind a **reverse proxy with access control**. It is not hardened for direct public internet exposure without additional measures.

Key responsibilities of the operator:
- Run the application behind HTTPS in production.
- Restrict access at the network or reverse-proxy level if needed.
- Protect secrets and the database from unauthorized access.

---

## 2. Authentication

The frontend authenticates requests using a **session token sent as an HTTP header** (`X-Api-Key`). This token is issued at login and stored in the browser.

**Current storage:** `localStorage`

- Cookies with `HttpOnly` + `SameSite` would be more resistant to token theft via XSS, but are not used today.
- The main risk with `localStorage` is that a **cross-site scripting (XSS)** vulnerability in the frontend could allow a malicious script to read and exfiltrate the token.

**Mitigations in place:**
- The frontend does not load any third-party scripts.
- The backend validates the token on every request.

**Recommendation:** Do not install unknown browser extensions or inject untrusted scripts into the page. If you extend the frontend, audit any third-party dependency carefully.

**Future improvement:** Moving to `HttpOnly` + `SameSite=Strict` session cookies would remove token access from JavaScript entirely. This would also require adding CSRF protection (see below).

### OIDC / SSO authentication

Link2NAS supports multiple OIDC providers configured via **Admin > SSO / OIDC**. Provider credentials (`client_secret`) are stored encrypted in the database — no OIDC credentials are held in `.env`.

**Session model (unchanged):** after a successful SSO login, Link2NAS issues a standard session token stored in `localStorage` and sent as `X-Api-Key` — identical to local login. No persistent auth cookie is introduced.

**Provider credentials:**
- `client_secret` is encrypted at rest with `V2_SECRET_ENCRYPTION_KEY` (Fernet/CryptoService).
- `client_secret` and `encrypted_client_secret` are never returned by any API endpoint.
- `GET /api/v2/public/app-info` exposes only `{ slug, button_label }` per provider — no credentials, no issuer, no client ID.

**Callback URL pattern:** each provider has its own slug in the redirect URI registered with the provider:
```
{PUBLIC_BASE_URL}/api/v2/auth/oidc/{slug}/callback
```

**State binding:** `oidc_states.provider_id` binds each state record to the issuing provider, preventing cross-provider state confusion.

**`l2n_oidc_exchange` cookie:**
- Short-lived (default 60 s, configurable per provider as `exchange_code_ttl_seconds`).
- Scoped to the `/api/v2/auth/oidc/complete` endpoint only (`Path` attribute).
- `HttpOnly` and `SameSite=Lax`.
- Deleted immediately after the exchange completes or fails.

**Security invariants:**
- `email_verified` is mandatory — tokens without a verified email claim are rejected.
- No `super_admin` can be created or promoted via OIDC. Auto-created accounts are always assigned `user` role.
- No `api_token`, session token, exchange code, or authorization code is placed in URLs.
- OIDC is not available in single-user mode (`LINK2NAS_SINGLE_USER_MODE=true`).

**HTTPS / reverse proxy:** the `Secure` cookie flag is set when `DEBUG=false`. In production, run behind HTTPS. TLS termination via a reverse proxy (nginx, Caddy, Traefik) is a deployment concern outside the scope of this release.

### Identity Proxy authentication

Link2NAS supports Identity Proxy authentication as an optional login method. A trusted reverse proxy (such as Cloudflare Access) authenticates the user and attaches a signed JWT in the `Cf-Access-Jwt-Assertion` header; Link2NAS validates the JWT to identify the user.

**Supported provider in v3.6:** Cloudflare Access (`cloudflare_access`) is the only supported and validated Identity Proxy provider. Other provider types are not supported unless explicitly documented in a future release.

**JWT validation (Cloudflare Access):**
- The JWT signature is verified against the JWKS endpoint at `https://{team_domain}/cdn-cgi/access/certs` — no shared secret is stored in Link2NAS.
- Link2NAS checks the signature algorithm (RS256 / ES256), the `iss` claim (must equal `https://{team_domain}`), the `aud` claim (must match the configured audience), and the `exp` claim.
- An invalid, missing, or expired JWT results in `401 Authentication failed`. Error details are never included in the response body.

**No JWT logged or returned:** the `Cf-Access-Jwt-Assertion` header value is never written to application logs and never included in error messages or API responses.

**Session model unchanged:** after a successful Identity Proxy login, Link2NAS issues a standard session token stored in `localStorage` and sent as `X-Api-Key` — identical to local login. No persistent auth cookie is introduced.

**Public app-info:** `GET /api/v2/public/app-info` exposes only `identity_proxy_enabled`, `identity_proxy_label`, `identity_proxy_auto_login`, and `identity_proxy_provider_type` — no `team_domain`, no `audience`, no internal config.

**Proxy trust:** `Cf-Access-Jwt-Assertion` must be set only by the trusted reverse proxy. Ensure Link2NAS is not directly reachable from the public internet without passing through the proxy, so that forged headers cannot be submitted directly.

**Auto-create:** if enabled, auto-created accounts are always assigned the `user` role. No `super_admin` can be created or promoted via Identity Proxy. Role promotion requires manual action in **Admin > Users**.

**Single-user mode:** Identity Proxy is not available when `LINK2NAS_SINGLE_USER_MODE=true`. All Identity Proxy endpoints return `404` in single-user mode.

**Mutual exclusivity with OIDC:** OIDC and Identity Proxy cannot be active simultaneously. Allowing both would create ambiguous authentication flows, conflicting identity mappings, and auto-login conflicts. Backend admin routes enforce this rule — enabling one is rejected while the other is active. `GET /api/v2/public/app-info` additionally suppresses OIDC data when Identity Proxy is active, as a defense-in-depth layer.

---

## 3. CSRF

CSRF is **not the primary risk in the current model.** The `X-Api-Key` header is not sent automatically by the browser — unlike cookies — so cross-origin requests cannot be authenticated without explicit JavaScript cooperation.

If authentication is ever migrated to cookies, **CSRF protection must be added at the same time**.

---

## 4. Secrets and encryption

### Application secrets

| Variable | Requirement |
|---|---|
| `FLASK_SECRET_KEY` | Required in production. Must be a strong random string (min 20 chars). Not a placeholder. |
| `V2_SECRET_ENCRYPTION_KEY` | Required in production. Must be a valid **Fernet** key. |

Generate a valid Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Starting with placeholders (`CHANGE_ME_*`, `change-me`, etc.) or a key shorter than 20 chars is **rejected at startup** when `DEBUG=false`.

### Key rotation warning

**Never lose or change `V2_SECRET_ENCRYPTION_KEY` without a migration strategy.** Secrets stored in the database (provider credentials, SMTP password, destination credentials) are encrypted with this key. Changing it without re-encrypting the data will make those secrets permanently unreadable.

### What is encrypted

- Provider API credentials (RealDebrid, AllDebrid, etc.)
- SMTP password
- Destination credentials

### API keys

User API keys are **hashed** (not stored in plaintext) and displayed only once at creation. A lost API key cannot be recovered — the user must generate a new one.

---

## 5. Environment files

- **`.env`** — private. Contains real secrets. Never commit it.
- **`.env.sample`** — public. Contains only documented placeholders. Safe to commit.

Do not commit:
- `.env` or any file containing real secrets
- Database dumps or SQLite files
- Log files
- Local exports or debug output

Run a secret scan before any public publication:
```bash
gitleaks detect --source . --verbose
```
If `gitleaks` is not available, use the grep patterns from the pre-publication checklist below.

---

## 6. Rate limiting and Redis

Rate limiting is available and enabled by default (`V2_RATE_LIMIT_ENABLED=true`).

| Mode | Behavior |
|---|---|
| No Redis | Falls back to in-process memory storage. Suitable for development or single-process deployments. |
| Redis | Shared state across multiple workers. Recommended in production. |

To require Redis at startup and refuse to start if unavailable:
```env
V2_RATE_LIMIT_REDIS_REQUIRED=true
```

---

## 7. Workers and queues

Link2NAS uses two separate RQ worker processes. Both must be running for full functionality:

```bash
# Main job queue
python worker.py

# Local download queue
python -m backend.services_v2.local_download_worker
```

If the local-download worker is not running, local download jobs will be enqueued but not processed until the dedicated worker is started.

---

## 8. Deployment recommendations

- **HTTPS:** Required in production. Use a reverse proxy (nginx, Caddy, Traefik) to terminate TLS.
- **Reverse proxy:** Recommended even on a private network. Adds header control, logging, and rate limiting at the edge.
- **Admin access:** Restrict the application to trusted users. The admin interface has destructive capabilities (user management, SMTP, system maintenance).
- **Database backups:** Back up the SQLite file (or PostgreSQL database) regularly. The database contains encrypted secrets — a backup without the matching `V2_SECRET_ENCRYPTION_KEY` is not useful.
- **Filesystem permissions:** Restrict access to `data/`, `logs/`, and `tmp/`. These directories may contain sensitive information.
- **Log rotation:** Configure log rotation to avoid unbounded disk growth.
- **Network isolation:** Do not expose Redis or PostgreSQL to the public internet. Bind them to localhost or a private network interface.

### Docker-specific recommendations

- **Never commit `.env`** — it contains real secrets. Use `.env.docker.sample` as the public template.
- **Set `POSTGRES_PASSWORD` and `V2_POSTGRES_DSN` in `.env`** before the first start. Both must use the same password. PostgreSQL writes this password into the `postgres_data` volume on initialization — changing `.env` afterwards does not update the database password. See [DOCKER.md](DOCKER.md#postgresql-password-management) for the procedure to change it after initialization.
- **Back up Docker volumes** regularly. Use `docker run` with volume mounts to extract the SQLite file, or `pg_dump` for PostgreSQL. Store backups with the matching `V2_SECRET_ENCRYPTION_KEY`.
- **Do not expose Redis or PostgreSQL ports** to the host unless required. In Docker Compose, neither service publishes ports by default — this is intentional.
- **Rate limiting in multi-container setups:** Set `V2_RATE_LIMIT_REDIS_REQUIRED=true` in `.env` so the app fails fast if Redis is not available, rather than falling back to per-process in-memory state that is not shared across containers.

---

## 9. GitHub publication checklist

Before pushing to a public repository:

```bash
# Scan for secrets in the current working tree
gitleaks detect --source . --verbose

# Check for untracked or modified files that should not be included
git status

# Verify no sensitive files are tracked
git ls-files | grep -iE '\.env$|\.sqlite|\.sqlite3|\.db$|\.log$'

# Verify .env.sample contains only placeholders
grep -E 'CHANGE_ME|your-|example\.' .env.sample
```

Confirm:
- [ ] `.env` is not tracked (`git ls-files .env` returns empty)
- [ ] No SQLite database, log files, or local exports are tracked
- [ ] `.env.sample` contains only placeholder values
- [ ] `DEBUG=false` and real secrets are configured in the deployment environment, not in committed files
- [ ] `FLASK_SECRET_KEY` and `V2_SECRET_ENCRYPTION_KEY` are not placeholders in production

---

## 10. Reporting security issues

If you discover a security issue, please **open a GitHub issue** describing the problem without including any secrets, tokens, or private data in the report.

If the issue requires confidential disclosure, contact the maintainer directly. A private reporting channel may be added in the future.
