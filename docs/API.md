# Link2NAS API Reference

Base URL: `http://<host>:<port>` (default `http://localhost:5000`)

All API routes use the prefix `/api/v2` unless stated otherwise.

---

## Authentication

### Multi-user mode

Every protected endpoint requires an `X-Api-Key` header carrying either:

- a **session token** obtained from `POST /api/v2/auth/login`, or
- a **user API key** created under `POST /api/v2/me/api-keys`.

```
X-Api-Key: l2n_a1b2c3d4.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Single-user mode

When `V2_SINGLE_USER_MODE=true`, authentication is bypassed. The `X-Api-Key` header is accepted but not required.

### User roles

| Role | Access |
|---|---|
| `user` | Own resources only |
| `super_admin` | All resources + admin endpoints |

---

## User API Keys and Scopes

API keys are created per user with an explicit list of scopes. The raw key is shown **once** at creation and is not stored — only a SHA-256 hash is kept.

Key format: `l2n_<8-char-hex-prefix>.<urlsafe-base64-secret>`

### Scopes

| Scope | Grants access to |
|---|---|
| `jobs:create` | Create, start, cancel, and manage jobs |
| `jobs:read` | Read job status and details |
| `qbittorrent:write` | qBittorrent compatibility endpoints |
| `extension` | Browser extension endpoints |
| `scripts` | Script / automation access |

Session tokens obtained via `POST /auth/login` carry implicit full user access. Scoped API keys are restricted to the listed scopes.

---

## Common HTTP Errors

| Status | Meaning |
|---|---|
| `400 Bad Request` | Missing or invalid request body / parameters |
| `401 Unauthorized` | Missing, invalid, or expired API key |
| `403 Forbidden` | Authenticated but insufficient role or scope |
| `404 Not Found` | Resource does not exist or belongs to another user |
| `429 Too Many Requests` | Rate limit exceeded |

Error responses include a JSON body:

```json
{ "error": "human-readable message" }
```

---

## Setup

These endpoints are active only before the first admin account is created.

### `GET /api/v2/setup/status`

Returns whether first-time setup is required.

**No auth required.**

```bash
curl http://localhost:5000/api/v2/setup/status
```

**Response**

```json
{ "setup_required": true }
```

---

### `POST /api/v2/setup/first-admin`

Creates the initial super-admin account. Fails if any user already exists.

**No auth required.**

**Body**

```json
{
  "email": "admin@example.com",
  "password": "changeme",
  "display_name": "Admin"
}
```

---

## Authentication Endpoints

### `POST /api/v2/auth/login`

Exchange email + password for a session token. Rate-limited.

**No auth required.**

**Body**

```json
{
  "email": "user@example.com",
  "password": "secret"
}
```

**Response**

```json
{
  "token": "l2n_...",
  "user": { "id": "...", "email": "...", "role": "user", ... }
}
```

**Curl example**

```bash
curl -s -X POST http://localhost:5000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

---

### `POST /api/v2/auth/logout`

Revokes the current session token server-side. The token is deactivated in the database immediately and will be rejected by all subsequent authenticated requests. Returns `200 {"ok": true}`.

The call is idempotent: if the token is already revoked or absent, it still returns `200 {"ok": true}`.

**Note:** Only session tokens (created at login or via magic login) are revoked. User API Keys created in Settings > API Keys are stored separately and are not affected.

```bash
curl -X POST http://localhost:5000/api/v2/auth/logout \
  -H "X-Api-Key: $TOKEN"
```

---

## Public Endpoints

No authentication required.

### `GET /api/v2/public/app-info`

Returns the application name, tagline, and whether email is available.

---

### `GET /api/v2/public/tokens/<raw_token>/status`

Checks whether an invitation, password-reset, magic-login, or email-verification token is still valid. Rate-limited.

---

### `POST /api/v2/public/invitations/accept`

Accepts an invitation and sets the initial password.

**Body**

```json
{ "token": "<invitation_token>", "password": "newpassword" }
```

---

### `POST /api/v2/public/magic-login/request`

Sends a magic login link to the given email address. Rate-limited.

**Body**

```json
{ "email": "user@example.com" }
```

---

### `POST /api/v2/public/magic-login/confirm`

Confirms a magic login token and returns a session token.

**Body**

```json
{ "token": "<magic_token>" }
```

---

### `POST /api/v2/public/password-reset/confirm`

Confirms a password-reset token and sets the new password.

**Body**

```json
{ "token": "<reset_token>", "password": "newpassword" }
```

---

### `POST /api/v2/public/email-verification/confirm`

Confirms an email-verification token.

**Body**

```json
{ "token": "<verification_token>" }
```

---

## User Profile (`/me`)

All endpoints in this section require `X-Api-Key`.

### `GET /api/v2/me`

Returns the current user's profile.

```bash
curl http://localhost:5000/api/v2/me \
  -H "X-Api-Key: $TOKEN"
```

**Response (partial)**

```json
{
  "id": "...",
  "email": "user@example.com",
  "display_name": "Alice",
  "role": "user",
  "preferred_language": "en",
  "ui_theme": "auto",
  "email_verified_at": "2025-01-01T00:00:00Z"
}
```

---

### `PATCH /api/v2/me`

Updates profile fields. All fields are optional.

**Body**

```json
{
  "display_name": "Alice",
  "email": "new@example.com",
  "preferred_language": "fr",
  "ui_theme": "night",
  "receive_application_emails": true
}
```

`ui_theme` accepted values: `auto`, `light`, `night`, `high_contrast`, `colorblind`.

---

### `POST /api/v2/me/password`

Changes the current user's password. Not available in single-user mode.

**Body**

```json
{
  "current_password": "old",
  "new_password": "new"
}
```

---

### `POST /api/v2/me/request-email-verification`

Sends a verification email to the current user. Rate-limited.

---

## User API Keys

### `GET /api/v2/me/api-keys`

Lists all API keys for the current user. Key secrets are never returned.

```bash
curl http://localhost:5000/api/v2/me/api-keys \
  -H "X-Api-Key: $TOKEN"
```

---

### `POST /api/v2/me/api-keys`

Creates a new API key. The full `raw_key` is returned **once** and cannot be retrieved again.

**Body**

```json
{
  "name": "Prowlarr key",
  "scopes": ["qbittorrent:write"]
}
```

**Response**

```json
{
  "id": "...",
  "name": "Prowlarr key",
  "scopes": ["qbittorrent:write"],
  "raw_key": "l2n_a1b2c3d4.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "created_at": "..."
}
```

**Curl example**

```bash
curl -s -X POST http://localhost:5000/api/v2/me/api-keys \
  -H "X-Api-Key: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"scripts","scopes":["jobs:create","jobs:read"]}'
```

---

### `POST /api/v2/me/api-keys/<key_id>/revoke`

Revokes a key (marks as inactive). Returns `204 No Content`.

---

### `DELETE /api/v2/me/api-keys/<key_id>`

Permanently deletes a key. Returns `204 No Content`.

---

## Integration Settings

### `GET /api/v2/me/integration-settings`

Returns the current user's integration settings (e.g. Prowlarr/qBittorrent config).

### `PUT /api/v2/me/integration-settings`

Updates integration settings. Enabling Prowlarr integration requires a user API key with the `qbittorrent:write` scope to exist.

---

## Jobs

Requires `X-Api-Key`. Creating jobs also requires the `jobs:create` scope when using a scoped API key; reading requires `jobs:read`.

### `GET /api/v2/jobs`

Lists jobs for the current user. Optional query parameter: `?status=<status>`.

```bash
curl "http://localhost:5000/api/v2/jobs?status=done" \
  -H "X-Api-Key: $TOKEN"
```

---

### `GET /api/v2/jobs/<job_id>`

Returns details for a single job.

```bash
curl http://localhost:5000/api/v2/jobs/$JOB_ID \
  -H "X-Api-Key: $TOKEN"
```

---

### `POST /api/v2/jobs`

Creates a new job.

**Body fields**

| Field | Required | Description |
|---|---|---|
| `source_type` | Yes | `magnet`, `direct_link`, `torrent_file` |
| `source_value` | Yes | The magnet URI, URL, or base64-encoded torrent |
| `provider_name` or `provider_config_id` | No | Debrid provider to use (defaults to user default) |
| `destination_name` or `destination_config_id` | No | Destination config (defaults to user default) |
| `send_to_destination` | No | Boolean — whether to push files to the destination |

**Curl example**

```bash
curl -s -X POST http://localhost:5000/api/v2/jobs \
  -H "X-Api-Key: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "magnet",
    "source_value": "magnet:?xt=urn:btih:...",
    "send_to_destination": false
  }'
```

---

### `POST /api/v2/jobs/<job_id>/start`

Starts a created-but-not-yet-started job.

### `POST /api/v2/jobs/<job_id>/cancel`

Cancels a running job.

### `POST /api/v2/jobs/<job_id>/restart`

Restarts a failed or cancelled job.

### `POST /api/v2/jobs/<job_id>/refresh`

Refreshes the status of a job from the debrid provider.

### `POST /api/v2/jobs/<job_id>/select-files`

Sets the file selection for a multi-file torrent job.

**Body**

```json
{ "file_ids": ["1", "3"] }
```

### `POST /api/v2/jobs/<job_id>/unrestrict-links`

Unrestricts the download links for a ready job.

### `POST /api/v2/jobs/<job_id>/send-to-destination/<destination_config_id>`

Sends job files to the specified destination.

### `POST /api/v2/jobs/<job_id>/cancel-local-download`

Cancels an in-progress local download for this job.

### `POST /api/v2/jobs/<job_id>/clone-with-provider`

Clones the job using a different provider config.

**Body**

```json
{ "provider_config_id": "..." }
```

### `DELETE /api/v2/jobs/<job_id>`

Deletes a job. Returns `204 No Content`.

---

## Providers

Requires `X-Api-Key`. Supported provider types: `realdebrid`, `alldebrid`.

### `GET /api/v2/providers`

Lists provider configurations for the current user.

### `POST /api/v2/providers`

Creates or updates a provider configuration.

**Body**

```json
{
  "provider_type": "realdebrid",
  "name": "My RD account",
  "api_key": "...",
  "is_enabled": true,
  "is_default": true
}
```

### `GET /api/v2/providers/<config_ref>`

Returns a single provider config by ID or name.

### `DELETE /api/v2/providers/<config_ref>`

Deletes a provider config.

---

## Destinations

Requires `X-Api-Key`. Supported destination types: `synology`, `local`.

### `GET /api/v2/destinations`

Lists destination configurations for the current user.

### `POST /api/v2/destinations`

Creates or updates a destination configuration.

**Body**

```json
{
  "destination_type": "synology",
  "name": "My NAS",
  "config_json": { ... },
  "is_enabled": true,
  "is_default": true
}
```

### `GET /api/v2/destinations/<config_ref>`

Returns a single destination config by ID or name.

### `POST /api/v2/destinations/<config_ref>/test`

Tests connectivity to the destination. Returns a status object.

### `DELETE /api/v2/destinations/<config_ref>`

Deletes a destination config.

---

## Notifications

Requires `X-Api-Key`.

### Notification Configs

Configs define delivery channels (email, Gotify, webhook, etc.).

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/notifications/configs` | List configs |
| `POST` | `/api/v2/notifications/configs` | Create config |
| `GET` | `/api/v2/notifications/configs/<id>` | Get config |
| `PUT` | `/api/v2/notifications/configs/<id>` | Update config |
| `DELETE` | `/api/v2/notifications/configs/<id>` | Delete config |
| `POST` | `/api/v2/notifications/configs/<id>/test` | Send test notification |

### Notification Rules

Rules define which events trigger which config.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/notifications/rules` | List rules |
| `POST` | `/api/v2/notifications/rules` | Create rule |
| `GET` | `/api/v2/notifications/rules/<id>` | Get rule |
| `PUT` | `/api/v2/notifications/rules/<id>` | Update rule |
| `DELETE` | `/api/v2/notifications/rules/<id>` | Delete rule |

### Notification Events

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/notifications/events` | List recent events (50–200) |

---

## System

Requires `X-Api-Key`.

### `GET /api/v2/system/provider`

Returns the current user's default provider status.

### `GET /api/v2/system/control-center`

Returns dashboard statistics: job counts, queue info, restart cooldowns.

---

## Provider Runtime

Requires `X-Api-Key`.

### `GET /api/v2/provider-runtime/me`

Returns account info from the current user's default debrid provider.

### `GET /api/v2/provider-runtime/test/<config_ref>`

Tests a specific provider config by ID or name.

---

## Public User Space

No authentication — uses a per-user public slug.

### `GET /u/<slug>/`

Lists files in the user's public space.

### `GET /u/<slug>/browse/<relative_dir>`

Lists files in a subdirectory of the public space.

### `GET /u/<slug>/files/<relative_path>`

Downloads a file from the public space.

---

## Admin Endpoints

All admin endpoints require `super_admin` role.

### User Management — `/api/v2/admin/users`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/users` | List all users |
| `POST` | `/api/v2/admin/users` | Create user |
| `PATCH` | `/api/v2/admin/users/<user_id>` | Update user |
| `DELETE` | `/api/v2/admin/users/<user_id>` | Delete user |
| `POST` | `/api/v2/admin/users/<user_id>/disable` | Disable user |
| `POST` | `/api/v2/admin/users/<user_id>/enable` | Enable user |
| `POST` | `/api/v2/admin/users/<user_id>/verify-email` | Mark email verified |
| `POST` | `/api/v2/admin/users/<user_id>/reset-password` | Force password reset |
| `POST` | `/api/v2/admin/users/<user_id>/invitation` | Create invitation token |
| `POST` | `/api/v2/admin/users/<user_id>/invitation/email` | Send invitation email |
| `POST` | `/api/v2/admin/users/<user_id>/password-reset-link` | Create reset token |
| `POST` | `/api/v2/admin/users/<user_id>/password-reset-link/email` | Send reset email |

**Create user body**

```json
{
  "email": "newuser@example.com",
  "password": "initial",
  "display_name": "Bob",
  "is_super_admin": false,
  "email_verified": true,
  "can_use_local_space": false,
  "force_password_change": true
}
```

**Curl example — list users**

```bash
curl http://localhost:5000/api/v2/admin/users \
  -H "X-Api-Key: $ADMIN_TOKEN"
```

---

### App Settings — `/api/v2/admin/app-settings`

Each section has a `GET` and a `PUT`:

| Endpoint | Section |
|---|---|
| `/api/v2/admin/app-settings/security` | Security settings |
| `/api/v2/admin/app-settings/cleanup` | Cleanup settings |
| `/api/v2/admin/app-settings/system-events` | System event settings |
| `/api/v2/admin/app-settings/runtime` | Runtime settings |
| `/api/v2/admin/app-settings/general` | General settings |

---

### SMTP Settings — `/api/v2/admin/smtp-settings`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/smtp-settings` | Get SMTP config |
| `PUT` | `/api/v2/admin/smtp-settings` | Save SMTP config |

---

### Announcements — `/api/v2/admin/announcements`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/announcements` | List announcements |
| `POST` | `/api/v2/admin/announcements` | Create announcement |
| `GET` | `/api/v2/admin/announcements/<id>` | Get announcement |
| `PATCH` | `/api/v2/admin/announcements/<id>` | Update announcement |
| `DELETE` | `/api/v2/admin/announcements/<id>` | Soft-delete announcement |
| `GET` | `/api/v2/admin/announcements/<id>/tracking` | Get read/acknowledge tracking |

Users can view their own active announcements at `GET /api/v2/announcements/active`.

---

### Email Templates — `/api/v2/admin/email-templates`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/email-templates` | List templates |
| `GET` | `/api/v2/admin/email-templates/<key>/<lang>` | Get template |
| `PUT` | `/api/v2/admin/email-templates/<key>/<lang>` | Save template |
| `POST` | `/api/v2/admin/email-templates/<key>/<lang>/preview` | Preview rendered template |
| `POST` | `/api/v2/admin/email-templates/<key>/<lang>/reset` | Reset to default |

---

### Notifications (Admin) — `/api/v2/admin/notifications`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/notifications/dispatcher/status` | Dispatcher status |
| `POST` | `/api/v2/admin/notifications/dispatcher/run-once` | Run dispatcher for a user |
| `POST` | `/api/v2/admin/notifications/events/test` | Create test event |
| `GET` | `/api/v2/admin/notifications/events` | List all notification events |

---

### Maintenance and Cleanup

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/maintenance/status` | Health and maintenance status |
| `POST` | `/api/v2/admin/cleanup/run` | Run cleanup task |
| `GET` | `/api/v2/admin/timeouts/restart-cooldowns` | Get cooldown config |
| `PUT` | `/api/v2/admin/timeouts/restart-cooldowns` | Save cooldown config |

---

### Anti-Abuse / Rate Limits — `/api/v2/admin/security`

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v2/admin/security/anti-abuse` | View rate limit counters |
| `POST` | `/api/v2/admin/security/anti-abuse/reset` | Reset all counters |
| `POST` | `/api/v2/admin/security/anti-abuse/reset/<kind>` | Reset a specific counter kind |

---

## qBittorrent Compatibility

> **Scope:** This compatibility layer is minimal and intended specifically for the **Prowlarr add-download flow**. It is not a full qBittorrent Web UI emulation. Most qBittorrent clients and features are not supported.

Prefix: `/qbittorrent/api/v2` (no `/api/v2` prefix)

Requires a user API key with the `qbittorrent:write` scope.

**Authentication** — any of the following are accepted:

| Method | Value |
|---|---|
| Header `Authorization` | `Bearer <api_key>` |
| Header `X-Api-Key` | `<api_key>` |
| Cookie `SID` | `<api_key>` |
| Form field `password` | `<api_key>` |

---

### `POST /qbittorrent/api/v2/auth/login`

Used by Prowlarr during initial setup. Accepts the API key as the `password` form field and returns the plain-text string `Ok.` on success or `Fails.` on failure.

```bash
curl -X POST http://localhost:5000/qbittorrent/api/v2/auth/login \
  -d "username=link2nas&password=l2n_a1b2c3d4.xxx"
```

---

### `GET /qbittorrent/api/v2/app/version`

Returns `"4.6.0"` — the emulated qBittorrent version string.

### `GET /qbittorrent/api/v2/app/webapiVersion`

Returns `"2.11.0"` — the emulated Web API version string.

### `GET /qbittorrent/api/v2/app/preferences`

Returns a minimal mock preferences object sufficient for client negotiation.

### `GET /qbittorrent/api/v2/torrents/info`

Returns an empty array. No real torrent state is maintained.

### `GET /qbittorrent/api/v2/torrents/categories`

Returns a mock categories object.

---

### `POST /qbittorrent/api/v2/torrents/add`

Submits a download to Link2NAS. This is the primary endpoint used by Prowlarr.

Accepts `multipart/form-data`:

| Field | Description |
|---|---|
| `urls` | Newline-separated magnet URIs or direct URLs |
| `torrents` | One or more `.torrent` file uploads |
| `category` | Optional category string (stored in audit log) |
| `stopped` / `paused` | Optional; ignored |

Each submission is recorded in an audit log with the input type, hash (if available), category, and final status.

Rate-limited per user.

**Curl example**

```bash
curl -X POST http://localhost:5000/qbittorrent/api/v2/torrents/add \
  -H "Authorization: Bearer l2n_a1b2c3d4.xxx" \
  -F "urls=magnet:?xt=urn:btih:..." \
  -F "category=movies"
```

On success returns HTTP `200` with body `Ok.`.

---

## Prowlarr Setup Summary

1. In Link2NAS, create a user API key with the `qbittorrent:write` scope.
2. In Prowlarr, add a **qBittorrent** download client:
   - Host: `<link2nas host>`
   - Port: `<link2nas port>`
   - Username: anything (ignored)
   - Password: the API key (`l2n_...`)
   - Category: optional
3. In Link2NAS, save a default provider and destination under your user settings so submitted jobs are processed automatically.

See [PROWLARR.md](PROWLARR.md) for the full integration guide.
