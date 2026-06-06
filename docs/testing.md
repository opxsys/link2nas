# Tests — Link2NAS

## Note on the API

Link2NAS V3 still mostly uses the `/api/v2/` HTTP API. Test scripts that call `/api/v2/` routes are active and relevant for V3; the `v2` prefix in their name does not make them legacy.

---

## scripts/ structure

```
scripts/
├── ci/                 CI Docker runners (used by GitHub Actions)
│   ├── test_docker_smoke_sqlite.sh   Start Docker (SQLite) → smoke → teardown
│   └── test_docker_smoke_postgres.sh Start Docker (PostgreSQL) → smoke → teardown
├── setup/              Initialization and configuration helpers
├── inspect/            Static route wiring checks
├── quality/            Code quality (compile, lint, secrets, unit tests)
│   ├── check_all.sh       Run all quality checks
│   ├── check_python.sh    Python compilation + lint
│   ├── check_frontend_js.sh  JavaScript syntax check
│   ├── check_secrets.sh   Secret detection (gitleaks + grep)
│   └── check_unit_tests.sh   Python unit tests (scripts/tests/unit/)
├── tests/
│   ├── unit/           Python unittest — no app required
│   ├── auth/           Authentication, tokens, auth policies
│   ├── admin/          User management, modes, permissions
│   ├── notifications/  Notifications, dispatcher, schema, deduplication
│   ├── email/          Email templates, SMTP sending, verification
│   ├── settings/       Global settings, maintenance, session, cleanup
│   ├── security/       Rate limits, secret exposure, timeouts
│   ├── qbittorrent/    qBittorrent API compatibility
│   ├── dev/            Development routes (not included by default)
│   └── manual/         Heavy manual tests (real NAS, live providers)
├── test_quality.sh     Static quality runner — no app required
├── test_v3_smoke.sh    Smoke runner — fast, no provider, called by ci/ scripts and test_v3_full.sh
├── test_v3_full.sh     Core test suite runner ★ (primary)
├── test_v3_sqlite.sh   SQLite backend wrapper → calls test_v3_full.sh
├── test_v3_postgres.sh PostgreSQL backend wrapper → calls test_v3_full.sh
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
| `ADMIN_PASSWORD` | _(empty)_ | Admin password — required unless `ADMIN_API_KEY` or `TOKEN` is set |
| `ADMIN_API_KEY` | _(empty)_ | Pre-obtained admin session token — skips login if provided |

The runner performs **one admin login at startup** and exports `ADMIN_API_KEY` to all child scripts. If `ADMIN_API_KEY` is already set (from a previous run or parent process), it is reused — no new login is performed. `ADMIN_PASSWORD` is never printed.

### For test_v3_postgres.sh

PostgreSQL must be available and configured. The wrapper sets a default dev DSN (`postgresql://link2nas:link2nas_dev_password@127.0.0.1:5432/link2nas_v2`). Override with `V2_POSTGRES_DSN` if needed.

### For email tests with real sending

Email tests do not require a live SMTP server by default. Real sending is only enabled when the following variables are set:

- `SMTP_RUN_TEST=true` — enables SMTP configuration tests
- `SMTP_RUN_SEND=true` — enables real message delivery

Without these variables, email tests only verify template rendering and configuration availability.

### For tests with a real provider or NAS

Tests requiring a live provider (RealDebrid, AllDebrid) or a real NAS are isolated in:

- `scripts/tests/manual/` — heavy manual tests, not included in automatic runners

---

## Runners

### Unit tests — Python unittest

```bash
bash scripts/quality/check_unit_tests.sh
```

Runs Python unit tests discovered in `scripts/tests/unit/` using `python3 -m unittest discover`. No running application is required — these tests exercise backend logic in isolation.

Current coverage:
- `test_destination_error.py` — destination failure classification, field assignment, and `error_message` isolation logic
- `test_provider_registry.py` — `PROVIDER_KEYS`, `PROVIDER_DISPLAY_NAMES`, and `build_provider()` correctness
- `test_destination_registry.py` — `DESTINATION_KEYS`, `DESTINATION_ALIAS_KEYS`, `DESTINATION_ALL_KEYS`, and display name completeness

To run a single test file directly:
```bash
python3 -m unittest scripts/tests/unit/test_destination_error -v
```

To run all quality checks including unit tests:
```bash
bash scripts/quality/check_all.sh
```

---

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

### test_v3_full.sh — Core test suite ★

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh
```

Runs the complete test suite against **the currently configured backend** (whatever `V2_DATABASE_BACKEND` is set to in the environment or `.env`). Performs a single admin login, exports `ADMIN_API_KEY` to all child scripts, and covers:

- Smoke: global settings, runtime settings, account tokens, anti-abuse, admin routes, qBittorrent rate limit
- Auth: policies, email verification
- Admin: user disable/enable, local space permission, public space
- Settings: session inactivity, cleanup, maintenance
- Notifications: schema, dispatcher, deduplication, business
- Email: transactional templates (no live SMTP by default)
- Security: rate limits, secret exposure, system events, timeouts
- qBittorrent: full API compatibility

If `ADMIN_API_KEY` is already available (e.g. from a parent script or a previous session), pass it directly to avoid a new login:

```bash
ADMIN_API_KEY=<token> bash scripts/test_v3_full.sh
```

Expected final output: `=== test_v3_full: OK ===`

Estimated duration: 10–20 minutes depending on environment.

> **Multi-backend release validation:** `test_v3_full.sh` tests one backend at a time. To validate both SQLite and PostgreSQL, run `test_v3_sqlite.sh` then `test_v3_postgres.sh` — each wrapper configures its backend and then calls `test_v3_full.sh`.

---

### test_v3_smoke.sh — Quick smoke

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh
```

Fast subset of tests against a running app. This runner is also called internally at the start of `test_v3_full.sh`.

Includes:

- Global settings (`test_app_settings`)
- Runtime settings (`test_runtime_settings`)
- Tokens and authentication (`test_account_tokens`)
- Admin anti-abuse (`test_admin_anti_abuse`)
- Admin users routes (`check_admin_users_routes`)
- qBittorrent rate limit (`test_qbittorrent_rate_limit`)

**Not included in the smoke runner:**

`test_single_user_mode.sh` and `test_multi_user_mode.sh` require a specific application configuration (`LINK2NAS_SINGLE_USER_MODE`). Run them manually in a dedicated environment.

If the application is not running, the smoke runner prints `[SKIP]` and exits cleanly (exit 0).

---

### test_v3_sqlite.sh — SQLite backend wrapper

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh
```

Sets `V2_DATABASE_BACKEND=sqlite`, clears any PostgreSQL DSN, then invokes `test_v3_full.sh`. Use this to run the full suite explicitly on the SQLite backend.

Expected output ends with:

```
=== test_v3_full: OK ===
=== test_v3_sqlite: OK ===
```

---

### test_v3_postgres.sh — PostgreSQL backend wrapper

```bash
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_postgres.sh
```

Sets `V2_DATABASE_BACKEND=postgres` with a default dev DSN, then invokes `test_v3_full.sh`. Use this to run the full suite explicitly on the PostgreSQL backend.

Override the DSN if your environment differs:

```bash
V2_POSTGRES_DSN="postgresql://link2nas:change_me@127.0.0.1:5432/link2nas_v2" \
  ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_postgres.sh
```

Expected output ends with:

```
=== test_v3_full: OK ===
=== test_v3_postgres: OK ===
```

---


## CI runners (GitHub Actions)

`scripts/ci/` contains scripts designed to run in GitHub Actions without any pre-existing application, secrets, or external services. Each script:

- generates ephemeral CI secrets using Python stdlib (no real secrets, no hardcoded values)
- starts Docker Compose from the appropriate sample `.env`
- waits for the app to become reachable
- creates the first admin (`admin@test.local` / `AdminPassword123!`)
- runs `scripts/test_v3_smoke.sh`
- tears down Docker with `down -v --remove-orphans` on exit, even on failure

### `scripts/ci/test_docker_smoke_sqlite.sh`

```bash
bash scripts/ci/test_docker_smoke_sqlite.sh
```

Uses `docker-compose.yml` with the SQLite backend. Runs the full smoke suite against the containerised app.

### `scripts/ci/test_docker_smoke_postgres.sh`

```bash
bash scripts/ci/test_docker_smoke_postgres.sh
```

Uses `docker-compose.yml` + `docker-compose.postgres.yml`. Waits up to 450 seconds for PostgreSQL to initialise and the app to become ready, then runs the smoke suite.

**Not run in standard CI:**

- Tests requiring a real debrid provider, real SMTP server, or real NAS
- `scripts/test_v3_full.sh` (too heavy for standard CI; run locally or in a dedicated `workflow_dispatch` job)

---

## When to use each runner

| Situation | Recommended |
|---|---|
| GitHub Actions — on every push | CI runs `quality` + `docker-smoke-sqlite` + `docker-smoke-postgres` automatically |
| Before every commit (local) | `test_quality.sh` + `check_unit_tests.sh` |
| After changing backend logic (no app needed) | `check_unit_tests.sh` |
| Quick sanity check after a code change | `test_v3_smoke.sh` |
| Full suite against current backend | `test_v3_full.sh` |
| Full suite — explicit SQLite backend | `test_v3_sqlite.sh` |
| Full suite — explicit PostgreSQL backend | `test_v3_postgres.sh` |
| Before a merge or release (both backends) | `test_v3_sqlite.sh` then `test_v3_postgres.sh` |
| After auth changes | `test_v3_smoke.sh` + `scripts/tests/auth/` |
| After notification changes | `test_v3_full.sh` |
| After email or SMTP changes | `test_v3_full.sh` (with `SMTP_RUN_TEST=true` if needed) |
| After qBittorrent/Prowlarr changes | `scripts/tests/qbittorrent/test_qbittorrent_compat.sh` |

---

## Quick commands

```bash
# Static quality only (no app required)
bash scripts/test_quality.sh

# Quick smoke
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh

# Full suite (uses backend from .env or environment)
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh

# Full suite — explicit SQLite backend
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh

# Full suite — explicit PostgreSQL backend
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_postgres.sh

# Single test script
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/tests/auth/test_account_tokens.sh

# Email templates only
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/tests/email/run_email_templates.sh
```

---

## Excluded by default

| Directory | Reason |
|---|---|
| `scripts/tests/dev/` | Development routes — not available in production |
| `scripts/tests/manual/` | Requires a real NAS or live provider — manual execution only |
| `scripts/inspect/` | Static wiring checks — no app required, run separately as needed |
| `scripts/tests/auth/test_account_expired_existing_token.sh` | Requires PostgreSQL + direct `docker exec` access — not part of SQLite runner |
