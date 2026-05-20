# Scripts — Link2NAS

Test runners and quality scripts for Link2NAS. Full documentation: [docs/testing.md](../docs/testing.md)

## Main runners

| Script | Description |
|---|---|
| `test_quality.sh` | Static quality checks (compile, lint, secrets) — no app required |
| `test_v3_smoke.sh` | Quick smoke — running app, no provider or SMTP |
| `test_v3_sqlite.sh` | Full suite — SQLite backend |
| `test_v3_postgres.sh` | Full suite — PostgreSQL backend |
| `test_v3_full.sh` | Full suite — SQLite + PostgreSQL (recommended before merge) |
| `test_v2_full.sh` | _(deprecated — replaced by `test_v3_full.sh`)_ |

## Quick start

```bash
# Static quality (no app required)
bash scripts/test_quality.sh

# Quick smoke
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_smoke.sh

# Full suite
ADMIN_EMAIL=admin@example.local ADMIN_PASSWORD=*** bash scripts/test_v3_full.sh
```

`ADMIN_PASSWORD` is required for all functional runners. The application must be running first.
