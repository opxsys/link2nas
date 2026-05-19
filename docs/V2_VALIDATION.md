# Link2NAS V2 — Validation

V2 validated with:

- SQLite full smoke test: OK
- PostgreSQL full smoke test: OK
- Real SMTP transactional emails: OK
- Account tokens: invitation, reset password, email verification, magic login: OK
- System notifications: OK
- Business notifications: OK
- Secret exposure checks: OK
- Rate-limit / anti-abuse checks: OK
- Maintenance / cleanup / runtime settings: OK

Notes:

- CSRF not required with current X-Api-Key auth model.
- Current rate-limit is in-process.
- Redis-backed rate-limit is postponed to V3/final hardening for Gunicorn multi-worker production.
- Docker/prod installation documentation is postponed to V3.
