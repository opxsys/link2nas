# Tests — Link2NAS

## Note on the API

Link2NAS V3 still mostly uses the `/api/v2/` HTTP API. Test scripts that call `/api/v2/` routes are active and relevant for V3; the `v2` prefix in their name does not make them legacy.

---

## scripts/ structure

```
scripts/
├── setup/              Initialization and configuration (DB, SMTP)
├── inspect/            Static route wiring checks
├── quality/            Code quality (compile, lint, secrets)
├── tests/
│   ├── auth/           Authentication, tokens, auth policies
│   ├── admin/          User management, modes, permissions
│   ├── notifications/  Notifications, dispatcher, schema, deduplication
│   ├── email/          Email templates, SMTP sending, verification
│   ├── settings/       Global settings, maintenance, session, cleanup
│   ├── security/       Rate limits, secret exposure, timeouts
│   ├── qbittorrent/    qBittorrent API compatibility
│   ├── v3/             V3-specific tests
│   ├── dev/            Development routes (not included by default)
│   └── manual/         Heavy manual tests (real NAS, live providers)
├── legacy/v1/          V1 scripts kept outside V3 runners
├── test_quality.sh     Static quality runner
├── test_v3_smoke.sh    Smoke runner (fast, no provider)
├── test_v3_sqlite.sh   Full suite — SQLite backend
├── test_v3_postgres.sh Full suite — PostgreSQL backend
├── test_v3_full.sh     Full suite — SQLite + PostgreSQL
└── test_v2_full.sh     V2 runner (deprecated)
```

---

## Prerequisites

### For all functional runners

The application must be running before executing HTTP-based tests:

```bash
python3 app.py
```

The following variables are required for functional runners:

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://127.0.0.1:5000` | Application URL |
| `ADMIN_EMAIL` | `admin@test.local` | Super admin account email |
| `ADMIN_PASSWORD` | _(empty — required)_ | Admin password. The runner exits immediately if absent. |

`ADMIN_PASSWORD` is never printed in runner output.

### For test_v3_postgres.sh

PostgreSQL must be available and configured (via `V2_DATABASE_BACKEND=postgres` or `V2_POSTGRES_DSN`).

### For email tests with real sending

Email tests do not require a live SMTP server by default. Real sending is only enabled when the following variables are set:

- `SMTP_RUN_TEST=true` — enables SMTP configuration tests
- `SMTP_RUN_SEND=true` — enables real message delivery

Without these variables, email tests only verify template rendering and configuration availability.

### For tests with a real provider or NAS

Tests requiring a live provider (RealDebrid, AllDebrid) or a real NAS are isolated in:

- `scripts/tests/manual/` — heavy manual tests, not included in automatic runners
- `scripts/legacy/v1/` — V1 scripts kept for reference, not included in V3 runners

---

## Runners

### test_quality.sh — Static quality

```bash
bash scripts/test_quality.sh
```

Checks code quality without starting the application:

- Python compilation (`compileall`)
- JavaScript syntax (frontend)
- Secret detection (`gitleaks` + defensive grep)

No running app required. Can be executed in CI on every commit.

---

### test_v3_smoke.sh — Quick smoke

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh
```

Fast tests against a running app, with no provider or live SMTP.

Includes:

- Global settings (`test_app_settings`)
- Runtime settings (`test_runtime_settings`)
- Tokens and authentication (`test_account_tokens`)
- Admin anti-abuse (`test_admin_anti_abuse`)
- Admin users routes (`check_admin_users_routes`)
- qBittorrent rate limit (`test_qbittorrent_rate_limit`)

**Not included in the smoke runner:**

`test_single_user_mode.sh` and `test_multi_user_mode.sh` require a specific application configuration (`LINK2NAS_SINGLE_USER_MODE`). Run them via `test_v3_sqlite.sh` in a dedicated environment.

If the application is not running, the runner prints `[SKIP]` and exits cleanly (exit 0).

---

### test_v3_sqlite.sh — Full SQLite suite

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh
```

Full suite on SQLite backend. Runs the smoke first, then:

- Auth: policies, expired tokens, email verification
- Admin: disable/enable, local space and public space permissions
- Settings: session inactivity, cleanup, maintenance
- Notifications: schema, dispatcher, deduplication, business
- Email: SMTP configuration, templates (no live sending by default)
- Security: rate limits, secret exposure, system events, timeouts
- qBittorrent: full API compatibility

Estimated duration: 10–20 minutes depending on environment.

To force the backend:

```bash
V2_DATABASE_BACKEND=sqlite ADMIN_EMAIL=... ADMIN_PASSWORD=... bash scripts/test_v3_sqlite.sh
```

---

### test_v3_postgres.sh — Full PostgreSQL suite

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** V2_POSTGRES_DSN=... bash scripts/test_v3_postgres.sh
```

Runs the same suite as `test_v3_sqlite.sh` with `V2_DATABASE_BACKEND=postgres`. PostgreSQL must be available and configured.

---

### test_v3_full.sh — Full SQLite + PostgreSQL suite

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh
```

Runs `test_v3_sqlite.sh` then `test_v3_postgres.sh` in sequence. Recommended before a merge or release.

---

### test_v2_full.sh — V2 runner (deprecated)

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v2_full.sh
```

Legacy runner, kept for compatibility. Prints a deprecation warning on startup. Replaced by `test_v3_full.sh`.

---

## When to use each runner

| Situation | Recommended runner |
|---|---|
| Before every commit | `test_quality.sh` |
| After a code change, quick sanity check | `test_v3_smoke.sh` |
| Before merging a feature branch | `test_v3_sqlite.sh` |
| Before a release | `test_v3_full.sh` |
| After auth changes | `test_v3_smoke.sh` + `scripts/tests/auth/` |
| After notification changes | `test_v3_sqlite.sh` (includes notification suite) |
| After email or SMTP changes | `test_v3_sqlite.sh` (with `SMTP_RUN_TEST=true` if needed) |
| After qBittorrent/Prowlarr compatibility changes | `scripts/tests/qbittorrent/test_qbittorrent_compat.sh` |

---

## Quick commands

```bash
# Static quality only (no app required)
bash scripts/test_quality.sh

# Quick smoke
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh

# Full SQLite suite
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh

# Full PostgreSQL suite
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** V2_POSTGRES_DSN=... bash scripts/test_v3_postgres.sh

# Full SQLite + PostgreSQL suite
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh

# Single test script
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/tests/auth/test_account_tokens.sh

# All email templates
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/tests/email/run_email_templates.sh
```

---

## Excluded by default

| Directory | Reason |
|---|---|
| `scripts/tests/dev/` | Development routes — not available in production |
| `scripts/tests/manual/` | Requires a real NAS or live provider — manual execution only |
| `scripts/legacy/v1/` | V1 architecture — kept for reference, not actively maintained |
| `scripts/inspect/` | Static wiring checks — no app required, run separately as needed |
