# Link2NAS

Link2NAS is a self-hosted job management application for debrid providers. It lets you submit magnets, `.torrent` files, or direct links, unrestrict them via RealDebrid or AllDebrid, and either retrieve the direct download links or automatically send the files to a destination — including local storage or a Synology NAS. Jobs, providers, and destinations are managed per user through a web interface.

---

## Project status

Link2NAS V3 is feature-complete and a publication candidate.

It is designed for self-hosted use on a trusted network. Validation on your own infrastructure is recommended before exposing it publicly. See [docs/SECURITY.md](docs/SECURITY.md) for deployment guidance.

---

## Features

- **Providers:** RealDebrid and AllDebrid, configured as per-user profiles
- **Destinations:** links-only, local storage, Synology NAS — per-user profiles
- **Jobs:** create, start, refresh, file selection, unrestrict, send, resend, cancel, restart, delete
- **Multi-file torrents:** browse and select individual files before sending
- **Batch upload:** submit multiple `.torrent` files in one operation
- **qBittorrent / Prowlarr compatibility:** API endpoint for remote add via `qbittorrent:write` scope
- **User API keys:** scoped keys with single-display secret, stored hashed
- **Notifications:** email, Gotify, webhook — per-user rules and event subscriptions
- **Admin announcements:** create and broadcast messages to users
- **Public user space:** optional per-user public file listing
- **UI themes:** auto/system, light, night, high-contrast, colorblind
- **Internationalization:** French and English
- **Single-user mode:** skip registration, lock the app to one account
- **Rate limiting:** configurable per endpoint, Redis-backed for multi-worker setups
- **Database:** SQLite (default) or PostgreSQL

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Frontend | Vanilla JS, no build step |
| Database | SQLite or PostgreSQL |
| Task queues | Redis + RQ |
| Encryption | Fernet (cryptography) |
| Auth | Token header (`X-Api-Key`) |

---

## Quick start

### Docker (recommended)

```bash
cp .env.docker.sample .env
# Edit .env — set FLASK_SECRET_KEY and V2_SECRET_ENCRYPTION_KEY at minimum

docker compose up -d --build
```

The app is available at `http://localhost:5000`. On first run, a setup page lets you create the initial admin account.

For PostgreSQL:
```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

See [docs/DOCKER.md](docs/DOCKER.md) for the full Docker deployment guide.

### Local (without Docker)

```bash
cp .env.sample .env
# Edit .env — set FLASK_SECRET_KEY, V2_SECRET_ENCRYPTION_KEY, and PUBLIC_BASE_URL at minimum

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python app.py
```

The app is available at `http://localhost:5000`.

Two background worker processes must be running for full functionality:

```bash
# Main job queue (debrid jobs, orchestration)
python worker.py

# Local download queue
python -m backend.services_v2.local_download_worker
```

If the local-download worker is not started, local download jobs will be enqueued but not processed until it is running.

---

## Security

Before running in production:

1. **Set a strong `FLASK_SECRET_KEY`** — minimum 20 characters, not a placeholder.
2. **Generate a valid `V2_SECRET_ENCRYPTION_KEY`:**
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
3. **Never commit `.env`** — it contains real secrets. `.env.sample` is the public template.
4. **Use HTTPS** — run behind a reverse proxy (nginx, Caddy, Traefik) in production.
5. **Do not lose `V2_SECRET_ENCRYPTION_KEY`** — provider and SMTP secrets stored in the database are encrypted with this key. Changing it without a migration will make them unreadable.

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model, rate limiting configuration, deployment recommendations, and the pre-publication checklist.

---

## Documentation

| File | Content |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Installation, workers, first setup, SQLite, PostgreSQL, Redis |
| [docs/DOCKER.md](docs/DOCKER.md) | Docker Compose deployment guide (SQLite + PostgreSQL) |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All environment variables with defaults and descriptions |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model, secrets, deployment hardening, publication checklist |
| [docs/testing.md](docs/testing.md) | Test runners, unit tests, prerequisites, quick commands |
| [docs/VALIDATION.md](docs/VALIDATION.md) | Pre-deployment validation checklist |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common symptoms and solutions |
| [docs/PROWLARR.md](docs/PROWLARR.md) | Prowlarr / qBittorrent integration guide |

---

## License

Link2NAS is licensed under the GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`).
