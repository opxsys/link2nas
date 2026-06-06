# Release Notes

## V3 / Next UI

### Summary

This release completes the V3 feature set and introduces the Next UI as the primary web interface. The legacy UI remains available for compatibility.

---

### New UI — Next UI (React + Vite + TypeScript)

The Next UI is a fully rebuilt frontend served under `/next`, now the primary interface for Link2NAS. It replaces the legacy Vanilla JS interface for day-to-day use while keeping the legacy UI available at its existing routes.

Key characteristics:

- React + Vite + TypeScript
- Tailwind CSS + shadcn/ui components
- Light theme by default; dark, high-contrast, and colorblind-friendly themes available
- Collapsible sidebar, desktop-first layout with mobile drawer support
- Full internationalisation: English and French
- Accessibility: ARIA labels, keyboard navigation, status badges with icon + text, not color alone

Pages implemented:

- Dashboard
- Jobs (list, detail, actions)
- New Job (magnet, direct link, .torrent file, batch upload)
- Settings (account, providers, destinations, API keys, notifications, Prowlarr)
- Notifications (channels, rules, event timeline)
- Admin (overview, general, users, SMTP, announcements, email templates, security, timeouts, runtime, cleanup, system events, maintenance)
- Prowlarr (embedded tab or fallback new-tab)
- Public token flows: `/invite`, `/verify-email`, `/reset-password`, `/magic-login`

---

### Admin — Announcements

- Global announcements enable/disable (Admin > Announcements).
- Per-announcement read/acknowledge/dismiss tracking.
- User-facing announcement banner with dismiss and acknowledge actions.
- Admin tracking view (opens, reads, acknowledges per announcement).
- Email delivery for announcements: only when SMTP is enabled and user has opted in to application announcement emails.
- Disabling global announcements preserves existing announcement records.

> **"Receive application emails" / "Recevoir les e-mails d'annonces applicatives"** — This user preference controls receipt of admin-sent application announcement emails only (maintenance notices, incidents, updates). It does not affect transactional/authentication emails (invitation, password reset, magic login, email verification). Those are always sent when required.

---

### Notifications

- User notification channels: email, Gotify, webhook.
- Per-user notification rules with severity threshold selection.
- Event timeline visible to users.
- Test notification from Admin > Runtime.
- System notifications visible to super admin.
- Notification dispatcher runtime setting (enabled/disabled from Admin).

---

### Provider / Destination Registry Scaffold

Provider and destination type keys are now centralised in two registry files:

- `backend/services_v2/provider_registry.py` — `PROVIDER_KEYS`, `PROVIDER_DISPLAY_NAMES`, `build_provider()`
- `backend/services_v2/destination_registry.py` — `DESTINATION_KEYS`, `DESTINATION_ALIAS_KEYS`, `DESTINATION_ALL_KEYS`, `DESTINATION_DISPLAY_NAMES`

Frontend type labels and icons are centralised in:

- `frontend-next/src/lib/provider-types.ts`
- `frontend-next/src/lib/destination-types.ts`

Previously, provider and destination type sets were duplicated across 7+ backend files and 4+ frontend components. All of these now import from the registries. See [PROVIDERS_DESTINATIONS.md](PROVIDERS_DESTINATIONS.md) for the developer guide on adding a new provider or destination.

---

### Docker / Infrastructure

- `WEB_CONCURRENCY=1` is the documented and applied default for all Docker deployments.
  - `docker-compose.yml` and `docker-compose.ghcr.yml` launch gunicorn with `-w "${WEB_CONCURRENCY:-1}"`.
  - Setting `WEB_CONCURRENCY` in `.env` is sufficient to change the worker count.
  - A single web worker does not limit concurrent users — job throughput is handled by the dedicated `worker`, `local-download-worker`, and `scheduler` services.
  - Increasing `WEB_CONCURRENCY` beyond `1` is an advanced configuration requiring explicit validation. See [CONFIGURATION.md](CONFIGURATION.md) for prerequisites.
- PostgreSQL fresh install validated with Docker Compose.

---

### Internationalisation

- All visible UI strings in Next UI are translated into English and French.
- Technical identifiers (Real-Debrid, AllDebrid, Synology, Redis, SMTP, Gotify, Webhook, HTTP, URL, API) are not translated.
- Translation keys are type-checked via `TranslationKey` — missing keys produce a compile error.

---

### Documentation added

| File | Content |
|---|---|
| [PROVIDERS_DESTINATIONS.md](PROVIDERS_DESTINATIONS.md) | Developer guide: how to add a provider or destination |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | This file |
| [NON_REGRESSION_CHECKLIST.md](NON_REGRESSION_CHECKLIST.md) | Manual non-regression checklist for pre-release validation |

---

### Compatibility

- The legacy UI and all its routes remain available and unmodified.
- All `/api/v2/` endpoints are unchanged.
- The Prowlarr / qBittorrent compatibility endpoint is unchanged.
- SQLite and PostgreSQL are both supported and validated.
- The `nas` type alias (`nas` → `synology`) is preserved in all validation paths.

---

### Version management — tracking item

The application version (`APP_VERSION`) defaults to `"unknown"` and is expected to be injected at build/release time via an environment variable or Docker build argument. It is not hardcoded in the source.

The recommended production pattern is to set `APP_VERSION` from the GitHub release tag, CI pipeline, or image build step. This is not yet implemented in the provided Docker or CI configuration. It is tracked as a future improvement — see [BACKLOG.md](BACKLOG.md).

---

### Migration from legacy UI

No migration is required. The Next UI is additive:

- The app serves the Next UI as the default interface.
- The legacy UI remains accessible and fully functional.
- All user data, provider profiles, destination profiles, jobs, and settings are shared between both interfaces via the same API.
- No manual migration step is required. The application applies its database schema automatically on startup.
