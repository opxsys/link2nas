# Scripts — Link2NAS

Test runners and quality scripts for Link2NAS. Full documentation: [docs/testing.md](../docs/testing.md)

## Quality checks (no app required)

| Script | Description |
|---|---|
| `quality/check_all.sh` | Run all quality checks (Python, JS, secrets, unit tests) |
| `quality/check_python.sh` | Python compilation and lint |
| `quality/check_frontend_js.sh` | JavaScript syntax check |
| `quality/check_secrets.sh` | Secret detection (gitleaks + grep) |
| `quality/check_unit_tests.sh` | Python unit tests (`tests/unit/`) |

## Functional runners (app must be running)

| Script | Description |
|---|---|
| `test_quality.sh` | Static quality checks (compile, lint, secrets) — no app required |
| `test_v3_smoke.sh` | Quick smoke — running app, no provider or SMTP |
| `test_v3_full.sh` | **Core test suite** — all tests, single admin login ★ |
| `test_v3_sqlite.sh` | SQLite backend wrapper → sets SQLite env, calls `test_v3_full.sh` |
| `test_v3_postgres.sh` | PostgreSQL backend wrapper → sets PostgreSQL env, calls `test_v3_full.sh` |
| `test_v2_full.sh` | _(deprecated — replaced by `test_v3_full.sh`)_ |

## Quick start

```bash
# All quality checks — no app required
bash scripts/quality/check_all.sh

# Unit tests only
bash scripts/quality/check_unit_tests.sh

# Static quality (no app required)
bash scripts/test_quality.sh

# Quick smoke
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh

# Full suite — current configured backend
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh

# Full release validation — SQLite then PostgreSQL
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_sqlite.sh
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_postgres.sh
```

`ADMIN_EMAIL` and `ADMIN_PASSWORD` are required for all functional runners unless `ADMIN_API_KEY` is set. The application must be running first. `ADMIN_PASSWORD` is never printed.
