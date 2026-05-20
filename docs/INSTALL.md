# Installation

## Prerequisites

- **Python 3.10+**
- **Redis** — required for RQ background workers; also recommended for rate limiting in multi-process deployments
- **SQLite** — default, no additional setup required
- **PostgreSQL** — optional alternative to SQLite
- **A RealDebrid or AllDebrid account** — if you intend to use a debrid provider

---

## Local installation

```bash
# 1. Copy the environment template
cp .env.sample .env

# 2. Edit .env — set at minimum:
#    FLASK_SECRET_KEY, V2_SECRET_ENCRYPTION_KEY, PUBLIC_BASE_URL
#    (see CONFIGURATION.md and the Secrets section below)

# 3. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## Minimal environment

Before starting, set at least these variables in `.env`:

```env
# Strong random string — minimum 20 characters
FLASK_SECRET_KEY=<strong-random-string>

# Valid Fernet key — generate with the command below
V2_SECRET_ENCRYPTION_KEY=<fernet-key>

# Public-facing URL of the app — required for email links
PUBLIC_BASE_URL=https://link2nas.example.com
```

Generate a Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Do not lose `V2_SECRET_ENCRYPTION_KEY`.** Provider and SMTP credentials stored in the database are encrypted with this key. Losing or changing it without a migration makes stored secrets permanently unreadable.

For Redis and database settings, see [CONFIGURATION.md](CONFIGURATION.md).

---

## Run the web application

```bash
python app.py
```

The app is available at `http://localhost:5000` by default (configurable via `HOST` and `PORT`).

---

## Run workers

Two worker processes must be running for background jobs to be processed:

```bash
# Main job queue — debrid jobs, orchestration
python worker.py

# Local download queue — transfers to local storage
python -m backend.services_v2.local_download_worker
```

If the local-download worker is not started, local download jobs will be enqueued but not processed until it is running.

---

## First setup

1. Open the app in your browser.
2. You will be redirected to the **setup page** on first run.
3. Create the first **Super Admin** account.
4. Log in, then go to **Settings** to configure your debrid provider (RealDebrid or AllDebrid).
5. Optionally configure a destination (local storage or Synology NAS), or leave it as links-only.

---

## SQLite (default)

SQLite requires no additional setup and is the recommended choice for single-user or small deployments.

- The database file is created at the path defined by `V2_SQLITE_PATH` (default: `./data/link2nas_v2.sqlite3`).
- **Back up both the database file and `V2_SECRET_ENCRYPTION_KEY` together.** A database backup without the matching key cannot decrypt stored credentials.

---

## PostgreSQL

Set the following in `.env`:

```env
V2_DATABASE_BACKEND=postgres
V2_POSTGRES_DSN=postgresql://link2nas:change_me@127.0.0.1:5432/link2nas_v2
```

The schema is applied automatically on startup. Do not expose PostgreSQL on a public network interface.

---

## Redis

Redis is required for the RQ workers. Configure it in `.env`:

```env
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_DB=0
```

In multi-worker deployments, Redis is also recommended for rate limiting (see `V2_RATE_LIMIT_REDIS_REQUIRED` in [CONFIGURATION.md](CONFIGURATION.md)).

---

## Validate your installation

Once the app and workers are running, run the automated test suite to verify the installation against the currently configured backend:

```bash
ADMIN_EMAIL="admin@example.local" ADMIN_PASSWORD="your-admin-password" bash scripts/test_v3_full.sh
```

Expected final output: `=== test_v3_full: OK ===`

For explicit backend targeting (SQLite or PostgreSQL), or for a full release validation covering both backends, use the dedicated wrappers — see [docs/testing.md](testing.md).

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Jobs remain in status `queued` indefinitely | A worker process is not running |
| Local downloads not progressing | The local-download worker is not started |
| `ValueError: Fernet key must be 32 url-safe base64-encoded bytes` | `V2_SECRET_ENCRYPTION_KEY` is not a valid Fernet key — regenerate it |
| `FLASK_SECRET_KEY is weak or a placeholder` at startup | Replace with a strong random string (min 20 chars) |
| Redis connection refused | Redis is not running or `REDIS_HOST`/`REDIS_PORT` are misconfigured |
| Provider API error | Provider credential is invalid or expired — re-enter it in Settings |
| Local download queue not moving | `local_download_worker` not running, or `downloads.local_worker.enabled=false` in Admin settings |
