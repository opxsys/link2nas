# Link2NAS Backlog

This document lists future ideas and technical improvements that are intentionally outside the current release scope.

These items are not required for the current stable release. They may be revisited later if the project grows, if production usage requires them, or if contributors want to work on them.

## V3 / Near-term

### PostgreSQL schema initialization lock / migration runner

All four application services (`web`, `worker`, `scheduler`, `local-download-worker`) call `create_app()` on startup. `create_app()` may apply `schema_postgres.sql` to initialize the database. On a fresh `postgres_data` volume, this creates a race condition: multiple processes attempt to create the same PostgreSQL types concurrently, causing a `UniqueViolation` on `pg_type`.

**Current workaround:** `docker-compose.postgres.yml` delays background services by `LINK2NAS_STARTUP_DELAY_SECONDS` (default: 20 seconds). This gives `web` time to complete schema initialization before the other services start.

**Correct fix:** Wrap the schema init path with `pg_advisory_xact_lock()` on the same connection that executes `schema_postgres.sql`. Only one process will hold the lock at a time; others will wait and then no-op because the schema already exists. Requirements:

- The advisory lock and the schema SQL must share the same connection or transaction.
- Rollback or a clear failure message on error.
- SQLite path is unaffected.
- After this is implemented, the startup delay in `docker-compose.postgres.yml` can be reduced to 0 or removed.

**Future extension:** Versioned schema migrations (e.g. a dedicated `schema-init` service or a lightweight migration table) would replace the current single-file apply-on-startup approach and eliminate the race entirely.

---

### Version number from CI / GitHub release

`APP_VERSION` defaults to `"unknown"` and is currently set manually as an environment variable in production. It is not injected automatically from the GitHub release tag, CI pipeline, or Docker image build.

The recommended future state: `APP_VERSION` should be set at build time from the Git tag or GitHub Actions release context (e.g. `$GITHUB_REF_NAME` or `--build-arg APP_VERSION=...` in the Dockerfile), so the displayed version always matches the published release without requiring manual `.env` changes.

This is not required for the current release. It is tracked here so it is not forgotten.

---

## V5 / Future Product Backlog

### Advanced operational dashboard

Potential future improvement: build a richer operational dashboard focused on real system activity, not cosmetic metrics.

Possible widgets:

- active jobs;
- provider errors;
- destination errors;
- jobs ready but not sent;
- jobs waiting for file selection;
- links-only jobs;
- local transfer/download activity;
- DB status;
- Redis status;
- worker status;
- scheduler status;
- storage usage;
- SMTP status;
- cleanup status;
- dispatcher/orchestrator status.

This is not required for the current release because existing pages already expose the necessary operational information.

### Email delivery journal

Potential future improvement: add an email sending log in `Admin > Emails`.

The journal could track:

- transactional emails;
- announcement emails;
- recipient metadata where safe;
- send status;
- failure reason;
- timestamps;
- retry/error context.

This would likely require a new backend model/table and a dedicated admin UI.

### Better proxy/backend-down errors

Potential future improvement: improve frontend handling of proxy/backend failures such as HTTP 502, backend unavailable, or reverse-proxy errors.

The UI should show a clear message such as:

> Backend unavailable or proxy error. Please check the Link2NAS server.

Instead of a generic request failure.

### Production hardening for multi-worker deployments

Current recommendation for PostgreSQL deployments is to keep `WEB_CONCURRENCY=1` unless multi-worker mode has been explicitly validated.

Future hardening work could include:

- Redis-backed rate limiting required for all web workers;
- startup/init safety with multiple workers;
- database migration/init race protection;
- scheduler uniqueness guarantees;
- worker/scheduler monitoring;
- operational alerts;
- production documentation for validated multi-worker setups.

This is not required for small self-hosted deployments. A single web worker can still serve multiple users because long-running work is handled by separate worker, scheduler, and local-download-worker services.
