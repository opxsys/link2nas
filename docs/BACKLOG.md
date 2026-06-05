# Link2NAS Backlog

This document lists future ideas and technical improvements that are intentionally outside the current release scope.

These items are not required for the current stable release. They may be revisited later if the project grows, if production usage requires them, or if contributors want to work on them.

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
