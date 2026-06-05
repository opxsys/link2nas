# Scripts — Link2NAS

Test runners and quality scripts for Link2NAS. Full documentation: [docs/testing.md](../docs/testing.md)

## Quality checks (no app required)

| Script | Description |
|---|---|
| `quality/check_all.sh` | Run all quality checks (Python, secrets, unit tests) |
| `quality/check_python.sh` | Python compilation and lint |
| `quality/check_secrets.sh` | Secret detection (gitleaks + grep) |
| `quality/check_unit_tests.sh` | Python unit tests (`tests/unit/`) |

## CI Docker runners (used by GitHub Actions)

These scripts start Docker Compose, wait for the app, create the first admin, run the smoke suite, and tear down cleanly. No real secrets, no real providers, no SMTP, no NAS.

| Script | Description |
|---|---|
| `ci/test_docker_smoke_sqlite.sh` | Start Docker (SQLite) → smoke → teardown |
| `ci/test_docker_smoke_postgres.sh` | Start Docker (PostgreSQL) → smoke → teardown |

## Functional runners (app must be running)

| Script | Description |
|---|---|
| `test_quality.sh` | Static quality checks (compile, lint, secrets) — no app required |
| `test_v3_smoke.sh` | Quick smoke — running app, no provider or SMTP |
| `test_v3_full.sh` | **Core test suite** — all tests, single admin login ★ |
| `test_v3_sqlite.sh` | SQLite backend wrapper → sets SQLite env, calls `test_v3_full.sh` |
| `test_v3_postgres.sh` | PostgreSQL backend wrapper → sets PostgreSQL env, calls `test_v3_full.sh` |

## Quick start

```bash
# All quality checks — no app required
bash scripts/quality/check_all.sh

# Unit tests only
bash scripts/quality/check_unit_tests.sh

# Static quality (no app required)
bash scripts/test_quality.sh

# CI Docker smoke — SQLite (starts + stops Docker automatically)
bash scripts/ci/test_docker_smoke_sqlite.sh

# CI Docker smoke — PostgreSQL (starts + stops Docker automatically)
bash scripts/ci/test_docker_smoke_postgres.sh

# Quick smoke (app must already be running)
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh

# Full suite — current configured backend
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh

# Full release validation — SQLite then PostgreSQL
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_postgres.sh
```

`ADMIN_EMAIL` and `ADMIN_PASSWORD` are required for functional runners unless `ADMIN_API_KEY` is set. The application must be running first (not needed for `ci/` scripts — they manage Docker themselves). `ADMIN_PASSWORD` is never printed.
