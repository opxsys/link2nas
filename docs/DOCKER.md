# Docker Deployment

Link2NAS ships with a Docker Compose configuration that runs all required services: Redis, the web application, the main job worker, the scheduler, and the local-download worker.

Two compose files are provided:

| File | Description |
|---|---|
| `docker-compose.yml` | Default configuration — SQLite database |
| `docker-compose.postgres.yml` | PostgreSQL override — use together with the base file |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/) v2 (the `docker compose` plugin)

---

## Quick start — SQLite (default)

SQLite requires no external database. This is the simplest setup.

```bash
# 1. Copy and edit the environment file
cp .env.docker.sample .env

# 2. Required: fill in FLASK_SECRET_KEY and V2_SECRET_ENCRYPTION_KEY
#    See "Environment file" below

# 3. Build and start all services
docker compose up -d --build

# 4. Check that all containers are running
docker compose ps
```

The web interface is available at `http://localhost:5000` once the `web` service is healthy.

---

## Quick start — PostgreSQL

The PostgreSQL override adds a `postgres` service and switches all application services to use it.

```bash
# 1. Copy the PostgreSQL-specific environment sample
cp .env.docker.postgres.sample .env

# 2. Open .env and set all three required values before the first start:
#      FLASK_SECRET_KEY=<strong-random-string>
#      V2_SECRET_ENCRYPTION_KEY=<fernet-key>
#      POSTGRES_PASSWORD=<your-chosen-password>
#    Also update V2_POSTGRES_DSN so its password matches POSTGRES_PASSWORD exactly:
#      V2_POSTGRES_DSN=postgresql://link2nas:<your-chosen-password>@postgres:5432/link2nas_v2

# 3. Build and start all services with both compose files
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build

# 4. Check that all containers are running
docker compose -f docker-compose.yml -f docker-compose.postgres.yml ps
```

**Important:** The PostgreSQL password is written into the `postgres_data` volume the first time the container starts. See [PostgreSQL password management](#postgresql-password-management) below for what happens if you need to change it after that.

To stop:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml down
```

---

## PostgreSQL password management

### Where the password is configured

The PostgreSQL password is configured exclusively in `.env`. Two values must always be identical:

```env
# Password embedded in the connection string used by the application
V2_POSTGRES_DSN=postgresql://link2nas:YOUR_PASSWORD@postgres:5432/link2nas_v2

# Password passed to the PostgreSQL container on first initialization
POSTGRES_PASSWORD=YOUR_PASSWORD
```

Both values must be set and must match before you run `docker compose up` for the first time on a clean `postgres_data` volume.

### Why changing `.env` alone is not enough after first start

The `POSTGRES_PASSWORD` variable is only read by the PostgreSQL container **once**, when the `postgres_data` volume is created for the first time. After that, the password is stored inside the volume. Changing `POSTGRES_PASSWORD` in `.env` and restarting the containers does not update the password already written in the database — it is silently ignored.

If the password in `V2_POSTGRES_DSN` does not match the one in the database, all application services will fail to connect with an authentication error.

### Changing the password — development or test environment

If you have no data worth keeping, the simplest approach is to destroy the volume and let PostgreSQL reinitialize:

```bash
# Stop all services and delete the postgres_data volume (all data is lost)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v

# Update POSTGRES_PASSWORD and V2_POSTGRES_DSN in .env, then restart
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

### Changing the password — production environment

Never run `down -v` in production. Instead, change the password inside the running database, then update `.env`:

```bash
# 1. Open a psql session in the running postgres container
docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec postgres \
  psql -U link2nas -d link2nas_v2

# 2. In the psql prompt, change the password
ALTER USER link2nas WITH PASSWORD 'your-new-password';
\q

# 3. Update both values in .env to the new password
#    V2_POSTGRES_DSN=postgresql://link2nas:your-new-password@postgres:5432/link2nas_v2
#    POSTGRES_PASSWORD=your-new-password

# 4. Restart the application services (not the postgres container itself)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml restart web worker scheduler local-download-worker
```

---

## Environment file

Two sample files are provided:

| File | Use when |
|---|---|
| `.env.docker.sample` | SQLite deployment (default) |
| `.env.docker.postgres.sample` | PostgreSQL deployment |

Copy the appropriate file to `.env` and set at minimum:

```env
# Strong random string — minimum 20 characters
FLASK_SECRET_KEY=<strong-random-string>

# Valid Fernet key — generate with:
# python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
V2_SECRET_ENCRYPTION_KEY=<fernet-key>

# Public-facing URL (used in email links, optional for local-only use)
PUBLIC_BASE_URL=http://localhost:5000
```

The Docker-specific paths (`DATA_DIR`, `TEMP_DIR`, `LOG_DIR`) are pre-configured in `.env.docker.sample` to match the container volume mounts — do not change them without also adjusting the volume configuration.

Redis connection variables (`REDIS_HOST=redis`, `REDIS_PORT=6379`) are set by the compose file itself and do not need to be in `.env`.

See [CONFIGURATION.md](CONFIGURATION.md) for the complete variable reference.

---

## Services

| Service | Container | Description |
|---|---|---|
| `redis` | `link2nas-redis` | Redis 7, AOF persistence enabled |
| `web` | `link2nas-web` | Gunicorn web application, port 5000 |
| `worker` | `link2nas-worker` | Main RQ job worker (debrid jobs, orchestration) |
| `scheduler` | `link2nas-scheduler` | Periodic job scheduler |
| `local-download-worker` | `link2nas-local-download-worker` | Local storage download queue processor |
| `postgres` *(optional)* | `link2nas-postgres` | PostgreSQL 16 (only with the postgres override) |

All services share the same image, built from the project `Dockerfile`. Only `redis` (and optionally `postgres`) use external images.

### Start order

- `redis` starts first.
- `web` starts after `redis`. The other services wait for `web` to start.
- `worker`, `scheduler`, and `local-download-worker` start after `web` (and `postgres`, when using the PostgreSQL override).

The `web` service exposes a health check at `GET /health` (interval: 30s, timeout: 5s, retries: 3).

---

## Monitoring endpoints

These endpoints are available without authentication and are suitable for health monitoring and startup validation:

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Returns `{"ok": true}` with HTTP 200. Used by Docker and any external monitor. |
| `/api/v2/setup/status` | GET | Returns `{"setup_required": true/false}`. Useful to verify the app is up and the database is accessible. Returns `setup_required: true` when no admin account exists yet. |

**Note:** `/api/status` is **not** a valid endpoint in this application — it is not registered and will return HTTP 404. Use `/health` for liveness checks and `/api/v2/setup/status` for a deeper application-level check.

```bash
# Liveness check
curl -fsS http://localhost:5000/health

# Application-level check (database + setup state)
curl -s http://localhost:5000/api/v2/setup/status
```

---

## Volumes

| Volume | Mount point | Contents |
|---|---|---|
| `link2nas_data` | `/app/data` | SQLite database, user data, uploaded torrents |
| `link2nas_downloads` | `/app/downloads` | Local destination downloads |
| `link2nas_tmp` | `/app/tmp` | Temporary files during processing |
| `link2nas_logs` | `/app/logs` | Application log files |
| `redis_data` | *(Redis internal)* | Redis AOF data |
| `postgres_data` *(optional)* | *(PostgreSQL internal)* | PostgreSQL data directory |

All volumes are Docker-managed named volumes. They persist across container restarts and `docker compose down`.

**To destroy all data and start fresh** (irreversible — development and testing only):
```bash
docker compose down -v
# For PostgreSQL:
docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v
```

Do not use `down -v` in production. See [PostgreSQL password management](#postgresql-password-management) for the production procedure to change credentials without data loss.

---

## First setup

On first run, Link2NAS detects an empty database and redirects to a setup page.

1. Open `http://localhost:5000` in your browser.
2. The setup page will appear automatically.
3. Create the first **Super Admin** account.
4. Log in and go to **Settings** to configure:
   - A debrid provider (RealDebrid or AllDebrid)
   - A destination (links-only, local storage, or Synology NAS)

---

## Useful commands

```bash
# View logs for all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f web
docker compose logs -f worker

# Restart a specific service
docker compose restart worker

# Rebuild and restart after a code change
docker compose up -d --build

# Open a shell in the web container
docker compose exec web bash

# Stop all services (volumes preserved)
docker compose down

# Stop all services and destroy all volumes (data loss)
docker compose down -v
```

---

## Upgrading

```bash
# Pull the latest code
git pull

# Rebuild and restart
docker compose up -d --build
```

The database schema is applied automatically on startup. No manual migration step is required.

**Before upgrading in production:**
- Back up the `link2nas_data` volume (see Backup below).
- Back up `V2_SECRET_ENCRYPTION_KEY` from your `.env` file.

---

## Backup

Back up both the data volume and the encryption key together. A database backup without the matching `V2_SECRET_ENCRYPTION_KEY` cannot decrypt stored credentials and is not useful for recovery.

```bash
# Export the SQLite database from the volume
docker run --rm \
  -v link2nas_data:/data \
  -v "$(pwd)":/backup \
  alpine cp /data/link2nas_v2.sqlite3 /backup/link2nas_backup_$(date +%Y%m%d).sqlite3

# For PostgreSQL: dump from the postgres container
docker compose exec postgres pg_dump -U link2nas link2nas_v2 > link2nas_backup_$(date +%Y%m%d).sql
```

Store the backup file and `V2_SECRET_ENCRYPTION_KEY` in a secure, separate location.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for a full list of symptoms and solutions.

| Symptom | Likely cause |
|---|---|
| `web` container exits immediately | `FLASK_SECRET_KEY` or `V2_SECRET_ENCRYPTION_KEY` is missing or a placeholder |
| Jobs remain `queued` | `worker` container is not running or crashed — check `docker compose logs worker` |
| Local downloads not progressing | `local-download-worker` container is not running |
| `connection refused` to Redis | `redis` container is not healthy — check `docker compose ps` |
| PostgreSQL not ready | `postgres` healthcheck not passing — wait a few seconds and retry |
| Port 5000 not reachable | Check that the `web` container is healthy: `docker compose ps` |
