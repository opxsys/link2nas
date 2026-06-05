# Validation checklist

This document provides a checklist of checks to run locally before deploying or publishing Link2NAS.

---

## Automated test suite

The application and workers must be running before executing the test suite.

### Single-backend validation (current configured backend)

```bash
ADMIN_EMAIL="admin@example.local" ADMIN_PASSWORD="your-admin-password" bash scripts/test_v3_full.sh
```

`test_v3_full.sh` runs the complete test suite against whichever backend is configured in the environment (SQLite by default). Expected result: `=== test_v3_full: OK ===`

Pass `ADMIN_API_KEY` directly to skip login if a token is already available:

```bash
ADMIN_API_KEY="<token>" bash scripts/test_v3_full.sh
```

### Multi-backend release validation (SQLite + PostgreSQL)

For a complete release validation covering both backends, run the two backend wrappers in sequence. Each wrapper forces its own backend configuration and then calls `test_v3_full.sh`:

```bash
# 1. SQLite backend
ADMIN_EMAIL="admin@example.local" ADMIN_PASSWORD="your-admin-password" bash scripts/test_v3_sqlite.sh
# Expected: === test_v3_full: OK === then === test_v3_sqlite: OK ===

# 2. PostgreSQL backend
ADMIN_EMAIL="admin@example.local" ADMIN_PASSWORD="your-admin-password" bash scripts/test_v3_postgres.sh
# Expected: === test_v3_full: OK === then === test_v3_postgres: OK ===
```

See [testing.md](testing.md) for the full runner documentation.

---

## 1. Static checks

### Python syntax
```bash
python3 -m compileall config.py app.py backend -q
```

No output means no syntax errors.

### Next UI
```bash
cd frontend-next && npm run type-check && npm run build
```

### Unit tests
```bash
bash scripts/quality/check_unit_tests.sh
```

Runs Python unit tests in `scripts/tests/unit/` — no running app required.

### All static + unit checks at once
```bash
bash scripts/quality/check_all.sh
```

---

## 2. Secret checks

### Scan for secrets in the working tree
Requires `gitleaks` to be installed ([github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)).

```bash
gitleaks detect --source . --verbose
```

### Check for untracked or modified files
```bash
git status --short
```

### Check for sensitive files tracked in git
```bash
git ls-files | grep -iE '\.env$|\.sqlite|\.sqlite3|\.db$|\.log$'
```

This should return no output. If it does, remove those files from tracking before publication.

---

## 3. Environment checks

- [ ] `.env` is not tracked: `git ls-files .env` returns empty
- [ ] `.env.sample` is present and contains only placeholder values
- [ ] `DEBUG=false` in the production environment
- [ ] `FLASK_SECRET_KEY` is set, strong, and not a placeholder
- [ ] `V2_SECRET_ENCRYPTION_KEY` is a valid Fernet key — verify with:
  ```bash
  python3 -c "
  from cryptography.fernet import Fernet
  import os
  key = os.environ.get('V2_SECRET_ENCRYPTION_KEY', '')
  Fernet(key.encode())
  print('Valid Fernet key')
  "
  ```
- [ ] `PUBLIC_BASE_URL` is set correctly (no trailing slash, reachable from the outside)

---

## 4. Endpoint checks

These endpoints require no authentication and can be used to verify the application is running correctly.

### Health check
```bash
curl -fsS http://localhost:5000/health
# Expected: {"ok": true}  (HTTP 200)
```

### Setup status
```bash
curl -s http://localhost:5000/api/v2/setup/status
# Expected: {"setup_required": true}  (before first admin is created)
# Expected: {"setup_required": false}  (after setup is complete)
```

**Note:** `/api/status` is not a valid endpoint — it returns HTTP 404. Use the two endpoints above for monitoring and validation.

---

## 5. Runtime checks

Run through these steps manually on a test instance before production deployment.

### Auth
- [ ] `GET /health` returns `{"ok": true}` with HTTP 200
- [ ] `GET /api/v2/setup/status` returns `{"setup_required": false}` after setup
- [ ] App starts without errors
- [ ] Setup page appears on first run
- [ ] Super Admin account can be created
- [ ] Login and logout work correctly

### Provider and destination
- [ ] Add a debrid provider (RealDebrid or AllDebrid) in Settings
- [ ] Provider test returns valid user info
- [ ] Add a destination (or confirm links-only works)

### Jobs
- [ ] Create a job from a magnet link
- [ ] Refresh the job status
- [ ] Unrestrict links
- [ ] Send to destination (or verify links appear in links-only mode)
- [ ] Restart a failed job
- [ ] Cancel a job
- [ ] Delete a job

### Workers
- [ ] `python worker.py` is running and processes queued jobs
- [ ] If local downloads are used: `python -m backend.services_v2.local_download_worker` is running
- [ ] Local download job progresses and completes

### Notifications
- [ ] Configure a notification channel in Settings
- [ ] Trigger a test notification from the Admin UI

### Announcements
- [ ] Create an announcement in Admin > Announcements
- [ ] Announcement appears in the UI for users

### Prowlarr (if used)
- [ ] API key with `qbittorrent:write` scope created
- [ ] Prowlarr test connection passes
- [ ] Prowlarr sends a test torrent — job appears in Link2NAS

---

## 6. SQLite validation

- [ ] Start the app with default `V2_DATABASE_BACKEND=sqlite`
- [ ] Create a user, provider, destination, and job
- [ ] Confirm data persists after restart
- [ ] Back up the SQLite file and `V2_SECRET_ENCRYPTION_KEY` together

---

## 7. PostgreSQL validation

If using PostgreSQL:

- [ ] Set `V2_DATABASE_BACKEND=postgres` and `V2_POSTGRES_DSN`
- [ ] Start the app — schema is applied automatically on first run
- [ ] Run the same smoke tests as SQLite above
- [ ] Confirm PostgreSQL is not exposed on a public network interface

---

## 8. Worker validation

- [ ] `worker.py` is running and consuming the main queue (`RQ_QUEUE_NAME`)
- [ ] `local_download_worker` is running and consuming the local-download queue (`RQ_LOCAL_DOWNLOAD_QUEUE_NAME`)
- [ ] Redis is accessible from both worker processes
- [ ] Queues drain normally — jobs do not pile up indefinitely
- [ ] Check queue sizes from Admin > Control Center if available

---

## 9. Docker validation

If deploying with Docker Compose, run these checks after `docker compose up -d --build`:

- [ ] All containers are running: `docker compose ps` — status `running` or `healthy` for all services
- [ ] `web` container passes health check: `docker compose ps` shows `healthy` (may take up to 60s on first start)
- [ ] Web interface accessible at `http://localhost:5000`
- [ ] Setup page appears on first run (clean database)
- [ ] `docker compose logs web` shows no startup errors
- [ ] `docker compose logs worker` shows the worker is consuming the queue
- [ ] `docker compose logs local-download-worker` shows the worker is running
- [ ] For PostgreSQL: `docker compose ps postgres` shows `healthy`
- [ ] `.env` is not tracked: `git ls-files .env` returns empty
- [ ] `docker-compose.postgres.yml` does not contain a real production password (use environment override or secrets management)

---

## 10. Pre-publication checklist

Before pushing to a public repository:

- [ ] Automated test suite passes on both backends: `bash scripts/test_v3_sqlite.sh` → `test_v3_sqlite: OK` and `bash scripts/test_v3_postgres.sh` → `test_v3_postgres: OK`
- [ ] No `.env` file tracked in git
- [ ] No SQLite database (`.sqlite3`, `.db`) tracked in git
- [ ] No log files tracked in git
- [ ] No local exports or debug output files tracked in git
- [ ] `README.md` is present and accurate
- [ ] `docs/SECURITY.md` is present
- [ ] `.env.sample` contains only placeholder values — no real keys, emails, or IPs
- [ ] `FLASK_SECRET_KEY` and `V2_SECRET_ENCRYPTION_KEY` in production are not placeholders
- [ ] `LICENSE` file is present, or documented as to be defined
- [ ] Secret scan completed (`gitleaks` or equivalent)
