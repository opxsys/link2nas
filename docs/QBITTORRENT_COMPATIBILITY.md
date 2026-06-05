# qBittorrent Compatibility API

Link2NAS provides a minimal qBittorrent-compatible API so external tools can submit magnets or `.torrent` files. This was primarily designed for Prowlarr, but it may also work with other tools that only require the basic qBittorrent add-torrent flow.

This compatibility layer is intentionally limited. Link2NAS is not a full qBittorrent client or emulator. It does not implement full torrent lifecycle management, seeding, ratio management, tracker management, or the full qBittorrent Web API.

The supported flow is:

```
external tool → qBittorrent-compatible add endpoint → Link2NAS job
    → configured debrid provider → configured destination or links-only mode
```

---

## Purpose

Link2NAS exposes a subset of the qBittorrent Web API at the path `/qbittorrent/api/v2/`. This allows external tools that support qBittorrent as a download client to send magnets and `.torrent` files to Link2NAS without needing a native Link2NAS integration.

The primary design goal was Prowlarr compatibility. The feature is documented under "Prowlarr" in the Link2NAS UI, but the underlying implementation is a generic qBittorrent compatibility layer that is not specific to Prowlarr.

---

## Supported use cases

- **Prowlarr** sending releases to Link2NAS as a qBittorrent download client — primary tested integration
- **External scripts** submitting magnet links or `.torrent` files programmatically
- **Other \*arr applications or tools** (Sonarr, Radarr, Lidarr, etc.) that only rely on the basic qBittorrent add-torrent flow — compatibility is possible but not guaranteed; each application must be tested independently

---

## Supported endpoints

All endpoints are mounted under the prefix `/qbittorrent/api/v2/`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/qbittorrent/api/v2/auth/login` | Authenticate with a Link2NAS API key |
| `GET` | `/qbittorrent/api/v2/app/version` | Return a fixed qBittorrent version string |
| `GET` | `/qbittorrent/api/v2/app/webapiVersion` | Return a fixed Web API version string |
| `GET` | `/qbittorrent/api/v2/app/preferences` | Return minimal preferences (save path stub) |
| `GET` | `/qbittorrent/api/v2/torrents/info` | Return an empty torrent list (no state tracking) |
| `GET` | `/qbittorrent/api/v2/torrents/categories` | Return the `prowlarr` category stub |
| `POST` | `/qbittorrent/api/v2/torrents/add` | Submit a magnet link or `.torrent` file |

### `/qbittorrent/api/v2/torrents/add` — accepted inputs

- **Magnet links or direct URLs** via the `urls` form field (newline-separated)
- **`.torrent` files** via the `torrents` multipart form field
- **`category`** field — accepted and stored in the audit record, not used for destination routing
- **`stopped` / `paused`** fields — accepted and ignored; jobs always start immediately

### Authentication

The `password` form field (used by Prowlarr's qBittorrent login flow) or the `X-Api-Key` request header are both accepted. The `username` field is ignored. A valid Link2NAS API key with the `qbittorrent:write` scope is required.

---

## What happens when a torrent is added

1. Link2NAS authenticates the request using the provided API key.
2. A standard Link2NAS job is created for the submitting user.
3. The job uses the user's **default provider** (RealDebrid or AllDebrid). If no default provider is configured, Link2NAS returns a clear error and no job is created.
4. The job uses the user's **default destination** if one is configured. If no destination is configured, the job is created in links-only mode and delivers direct download URLs instead.
5. The `category` field sent by the external tool is recorded in the submission audit log but does not affect provider or destination selection.
6. The endpoint returns `Ok.` on success — the standard qBittorrent response string.

---

## Limitations

Link2NAS is not a full qBittorrent emulator. The following are explicitly not supported:

- Full torrent lifecycle management (piece tracking, progress reporting)
- Seeding or upload ratio management
- Tracker management or announce URLs
- Peer/swarm information
- Pause and resume semantics as defined by qBittorrent
- Per-category routing to different destinations
- File priority or selective file download within a torrent (handled separately via Link2NAS job file selection, not via the qBittorrent API)
- The full `/qbittorrent/api/v2/torrents/*` API surface beyond the endpoints listed above
- Advanced tag behavior
- qBittorrent WebUI — only the API endpoints required for remote add are implemented

Tools that poll for torrent state, expect seeding status, or rely on rich qBittorrent lifecycle callbacks will not work correctly.

---

## Compatibility expectations

**Prowlarr** is the primary tested integration and is expected to work reliably.

**Other clients** may work if they only require:
- Login to verify connectivity
- Version/preferences check
- Add torrent (magnet or file)
- Optionally: list torrents (returns empty)

Clients that require full qBittorrent behavior — including state polling, seeding confirmation, ratio tracking, or detailed torrent metadata — may fail silently, behave partially, or produce incorrect results. Test each integration independently before relying on it.

---

## Security notes

- Create a **dedicated API key** for each external tool — do not reuse session tokens or keys with broader scopes.
- API keys must have the **`qbittorrent:write`** scope. Keys without this scope are rejected at the login step.
- **Revoke keys immediately** from Settings > API Keys if a key is exposed or compromised.
- The `username` form field is ignored entirely — authentication is based solely on the API key.
- If the external tool communicates with Link2NAS over a network (not localhost), use **HTTPS**.
- Magnet links and torrent file names are **not logged in full** — only a hash of the content is recorded in audit logs to allow incident tracing without exposing private tracker URLs or magnet parameters.
- Link2NAS acts on behalf of the **authenticated user** whose API key was used. Jobs, provider selection, and destination selection are all scoped to that user.
- See [SECURITY.md](SECURITY.md) for the full API key security model.

---

## Naming note

The Link2NAS UI currently labels this feature as "Prowlarr" because Prowlarr is the primary tested use case. The underlying implementation is a qBittorrent Compatibility API that is not specific to Prowlarr.

Future UI or documentation updates may rename the section from "Prowlarr" to "qBittorrent Compatibility" while retaining Prowlarr-specific setup guidance. The API paths, authentication model, and behavior described in this document will remain stable regardless of how the feature is labeled in the UI.

For the step-by-step Prowlarr setup guide, see [PROWLARR.md](PROWLARR.md).
