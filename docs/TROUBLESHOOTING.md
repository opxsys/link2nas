# Troubleshooting

Common symptoms and solutions for Link2NAS installations.

---

## Health and monitoring endpoints

### Which endpoints can I use to verify the app is running?

Two endpoints are available without authentication:

| Endpoint | Expected response |
|---|---|
| `GET /health` | `{"ok": true}` — HTTP 200 |
| `GET /api/v2/setup/status` | `{"setup_required": false}` — HTTP 200 (after setup) |

```bash
curl -fsS http://localhost:5000/health
curl -s http://localhost:5000/api/v2/setup/status
```

### `GET /api/status` returns 404

`/api/status` is not a registered endpoint. Use `/health` for liveness checks. This URL may appear in external monitoring guides or older documentation — it does not exist in this application.

---

## Application startup

### `FLASK_SECRET_KEY is weak or a placeholder`

**Symptom:** The application refuses to start with a message about a weak or placeholder secret key.

**Cause:** `FLASK_SECRET_KEY` is missing, too short (under 20 characters), or set to a known placeholder (`change-me`, `CHANGE_ME_*`, etc.).

**Fix:** Generate a strong random value and set it in `.env`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

### `ValueError: Fernet key must be 32 url-safe base64-encoded bytes`

**Symptom:** The application exits at startup with a Fernet key validation error.

**Cause:** `V2_SECRET_ENCRYPTION_KEY` is not set, is a placeholder, or is not a valid Fernet-format key.

**Fix:** Generate a valid Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the output as `V2_SECRET_ENCRYPTION_KEY` in `.env`. **Do not lose this key** — it is required to decrypt provider and SMTP credentials stored in the database.

---

### `ImportError` or `ModuleNotFoundError` at startup

**Cause:** Dependencies are not installed.

**Fix:**
```bash
pip install -r requirements.txt
```

If using a virtual environment, activate it first: `source .venv/bin/activate`.

---

## Jobs and workers

### Jobs remain in status `queued` indefinitely

**Cause:** The main worker process (`worker.py`) is not running.

**Fix (local):**
```bash
python worker.py
```

**Fix (Docker):**
```bash
docker compose ps
docker compose logs worker
docker compose restart worker
```

---

### Local downloads not progressing

**Cause:** The local-download worker is not running.

**Fix (local):**
```bash
python -m backend.services_v2.local_download_worker
```

**Fix (Docker):**
```bash
docker compose logs local-download-worker
docker compose restart local-download-worker
```

If the worker is running but local downloads still do not progress, check **Admin > Settings** and confirm that the local download worker is not disabled there (`downloads.local_worker.enabled`).

---

### Jobs fail immediately after creation

**Likely causes:**
- Provider credential is invalid or expired — re-enter it in **Settings > Providers**.
- The user has no default provider configured — configure one in **Settings > Providers**.
- The debrid provider API is unreachable (network issue).

**Diagnostic:** Open the failed job and check the error message in the Technical section.

---

### Jobs are created but destination send always fails

**Likely causes:**
- Destination credential is incorrect (NAS address, port, username, or password).
- The NAS is unreachable from the server running Link2NAS.
- The destination service (e.g. Synology DSM) is not running or not listening on the configured port.

**Fix:** In **Settings > Destinations**, review and test the destination configuration.

---

## Database

### Redis connection refused

**Symptom:** Application or worker exits with `Connection refused` pointing to Redis.

**Cause:** Redis is not running, or `REDIS_HOST`/`REDIS_PORT` are misconfigured.

**Fix (local):** Start Redis:
```bash
redis-server
```

**Fix (Docker):**
```bash
docker compose ps redis
docker compose logs redis
docker compose restart redis
```

Verify the Redis variables in `.env`:
```env
REDIS_HOST=127.0.0.1  # local install
REDIS_HOST=redis       # Docker Compose
REDIS_PORT=6379
REDIS_DB=0
```

---

### Redis warning: Memory overcommit must be enabled

**Symptom:** Redis logs show this warning:

```text
WARNING Memory overcommit must be enabled!
```

**Cause:** The Docker host has `vm.overcommit_memory` disabled. Redis can still start, but background save or persistence operations may fail under memory pressure.

**Fix:** Enable memory overcommit immediately and persist it across reboots:

```bash
sudo sysctl vm.overcommit_memory=1
echo 'vm.overcommit_memory=1' | sudo tee /etc/sysctl.d/99-link2nas-redis.conf
sudo sysctl --system
```

Then restart Redis if needed:

```bash
docker compose restart redis
```

Verify:

```bash
sysctl vm.overcommit_memory
```

Expected output:

```text
vm.overcommit_memory = 1
```

---

### PostgreSQL connection refused or authentication failed

**Cause:** PostgreSQL is not running, the DSN is incorrect, or the role/database does not exist.

**Fix:** Verify `V2_POSTGRES_DSN` in `.env`:
```env
V2_POSTGRES_DSN=postgresql://link2nas:<password>@127.0.0.1:5432/link2nas_v2
```

In Docker, the hostname must be the Docker Compose service name:
```env
V2_POSTGRES_DSN=postgresql://link2nas:<password>@postgres:5432/link2nas_v2
```

Check that `POSTGRES_USER`, `POSTGRES_DB`, and `POSTGRES_PASSWORD` in `.env` are set and that `POSTGRES_PASSWORD` matches the password in `V2_POSTGRES_DSN`.

---

### PostgreSQL authentication failure after changing `POSTGRES_PASSWORD` in `.env`

**Symptom:** Application services fail to connect to PostgreSQL after updating `POSTGRES_PASSWORD` and `V2_POSTGRES_DSN` in `.env` and restarting.

**Cause:** `POSTGRES_PASSWORD` is only used by the PostgreSQL container image when the `postgres_data` volume is created for the first time. Once the volume exists, changing `POSTGRES_PASSWORD` in `.env` and restarting has no effect on the password stored in the database. The new value in `V2_POSTGRES_DSN` no longer matches the password the database was initialized with.

**Fix — development or test environment (data loss):**

If the data can be discarded:
```bash
# Stop all services and destroy the postgres_data volume
docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v

# Update POSTGRES_PASSWORD and V2_POSTGRES_DSN in .env, then restart
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

**Fix — production environment (no data loss):**

Change the password inside the running database, then update `.env`:
```bash
# 1. Open a psql session in the running postgres container
docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec postgres \
  psql -U link2nas -d link2nas_v2

# 2. In the psql prompt, set the new password
ALTER USER link2nas WITH PASSWORD 'your-new-password';
\q

# 3. Update both values in .env
#    POSTGRES_PASSWORD=your-new-password
#    V2_POSTGRES_DSN=postgresql://link2nas:your-new-password@postgres:5432/link2nas_v2

# 4. Restart the application services (not the postgres container itself)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
  restart web worker scheduler local-download-worker
```

**Prevention:** Set `POSTGRES_PASSWORD` and `V2_POSTGRES_DSN` to their final values in `.env` before running `docker compose up` for the first time on a clean `postgres_data` volume.

---

### PostgreSQL fresh install: `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`

**Symptom:** One or more background service containers (`worker`, `scheduler`, or `local-download-worker`) log an error like:

```text
psycopg.errors.UniqueViolation: duplicate key value violates unique constraint "pg_type_typname_nsp_index"
DETAIL: Key (typname, typnamespace)=(users, 2200) already exists.
```

**Cause:** On a fresh `postgres_data` volume, multiple application containers call `create_app()` and attempt to apply the schema concurrently. PostgreSQL rejects the duplicate type creation from whichever process loses the race.

**Immediate check:** If the containers restart automatically (`restart: unless-stopped`) and the `web` service has already completed schema initialization, the affected containers will typically start successfully on their next restart. Check `Admin > Maintenance` — if the app is operational there, the instance is healthy.

**Fix — prevent the race:**

`docker-compose.postgres.yml` applies a startup delay to the background services via `LINK2NAS_STARTUP_DELAY_SECONDS` (default: 20 seconds). If you are not using this override, add it or start services in two steps:

```bash
# Step 1 — web and infrastructure only
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
  up -d postgres redis web

# Wait for web to become healthy
sleep 20

# Step 2 — background services
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
  up -d worker scheduler local-download-worker
```

**Future fix:** The correct solution is a `pg_advisory_xact_lock()` guard in the schema init path so only one process applies the schema at a time. This is tracked in the backlog.

---

### Database schema not applied

**Symptom:** The app starts but API calls fail with table-not-found errors.

**Cause:** The schema migration did not run.

**Fix:** The schema is applied automatically on startup. Restart the application. If it still fails, check the startup logs for schema errors.

---

## Single-user mode

### After switching from single-user to multi-user, login fails

**Symptom:** After setting `LINK2NAS_SINGLE_USER_MODE=false` on an instance that previously ran in single-user mode, the login page appears but the single-user account cannot authenticate with a password.

**Cause:** The auto-created single-user account may have `password_hash=None`. In single-user mode, no password is required — the account is accessed without credentials. Switching back to multi-user mode on the same database leaves this account in a state that is incompatible with classic password login.

**This is not a supported migration path.** Switching modes on an existing production database is not a guaranteed-safe operation.

**Options:**

1. **Fresh database (test or new deployment):** destroy the volumes and start over:
   ```bash
   docker compose down -v
   # Update LINK2NAS_SINGLE_USER_MODE=false in .env, then restart
   docker compose up -d --build
   ```

2. **Recover without data loss (advanced):** use a direct database session to assign a password hash or create a new super admin account manually, then proceed with multi-user mode. This requires knowledge of the database schema and Werkzeug password hashing.

3. **Recommended:** choose the deployment mode once, before the first startup. Do not change it on an existing production database.

See [CONFIGURATION.md](CONFIGURATION.md) for the full warning and the difference between single-user and multi-user modes.

---

## Destinations (NAS / local)

### Destination status: "Connection refused"

The NAS address or port is wrong, or the Synology service is not listening. Verify the destination configuration in **Settings > Destinations** and confirm the NAS is reachable from the server.

---

### Destination status: "Connection timed out"

The NAS is unreachable (network issue, firewall, or wrong IP). Confirm the NAS is online and accessible from the host running Link2NAS.

---

### Destination status: "Authentication failed"

The NAS username or password is incorrect. Update the credential in **Settings > Destinations**.

---

### Local download: file not appearing in destination folder

- Confirm `USERDATA_DIR` is set correctly and the process has write permission to that path.
- In Docker, confirm the `link2nas_downloads` volume is mounted at `/app/downloads` and is accessible.

---

## Prowlarr / qBittorrent integration

### Prowlarr test returns "Unauthorized"

The API key is incorrect, missing, or does not have the `qbittorrent:write` scope. Create a new key in **Settings > API Keys** with the correct scope and update the Prowlarr configuration.

---

### Prowlarr test passes but no jobs are created

The user associated with the API key has no default provider configured. Go to **Settings > Providers** and set a default.

---

### Jobs are created by Prowlarr but fail immediately

The provider rejected the torrent — check the job error message. This usually means the provider API key is invalid or expired.

---

### Prowlarr cannot reach Link2NAS

Verify the host, port, and SSL settings in Prowlarr. Confirm Link2NAS is accessible from the Prowlarr host on the configured port.

---

## Docker-specific

### Container exits immediately after `docker compose up`

Check the exit log:
```bash
docker compose logs web
```

The most common causes are a missing or invalid `FLASK_SECRET_KEY` or `V2_SECRET_ENCRYPTION_KEY`.

---

### Port 5000 not accessible from the host

Confirm the `web` service is healthy:
```bash
docker compose ps
```

If the status is not `healthy`, check the logs. The health check polls `GET /health` every 30 seconds with a 5-second timeout and 3 retries.

---

### Changes to `.env` not applied after restart

Docker Compose reads `.env` at container creation time. After editing `.env`, recreate the containers:
```bash
docker compose up -d
```

(Not just `docker compose restart` — that reuses existing container configuration.)

---

### How to completely reset the installation

This permanently deletes all data, volumes, and containers:
```bash
docker compose down -v
```

After this, the next `docker compose up` will start from a clean state, including a new first-setup flow.

---

## Email / SMTP

### Outbound emails not delivered

- SMTP is configured through **Admin > SMTP**, not via environment variables.
- Confirm the SMTP credentials are correct and the mail server is reachable.
- Verify `PUBLIC_BASE_URL` is set correctly — it is used in all email links.

---

### Magic login / invitation / password reset links are broken

`PUBLIC_BASE_URL` is set incorrectly or is not reachable from outside. Set it to the exact public URL where Link2NAS is accessible (no trailing slash, correct scheme).

---

## Quality and test runners

### `check_unit_tests.sh` fails with `ModuleNotFoundError`

The unit test module resolver relies on the project root being in the Python path. Run the script from the project root directory:
```bash
bash scripts/quality/check_unit_tests.sh
```

Do not run test files directly with `python3` unless you set `PYTHONPATH` manually.

---

### `test_v3_full.sh` fails with `connection refused`

The application must be running before executing functional tests. Start the app (and workers) first, then run the test suite.

---

### `gitleaks` not found

Install it from [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks), or skip the secret scan step and verify `.env.sample` manually — it must contain only placeholder values.
