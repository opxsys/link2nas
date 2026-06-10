# Prowlarr Integration

> For the technical scope and limitations of the qBittorrent compatibility endpoints, see [QBITTORRENT_COMPATIBILITY.md](QBITTORRENT_COMPATIBILITY.md).

## Overview

Link2NAS integrates with Prowlarr in two independent ways.

**Mode A — Send from Prowlarr:** Prowlarr submits a magnet or `.torrent` file to Link2NAS via a qBittorrent-compatible API. Use this when you want to trigger downloads directly from the Prowlarr UI.

**Mode B — Native search in Link2NAS:** You search Prowlarr indexers from within the Link2NAS interface (`/prowlarr`), browse results, and create jobs without leaving Link2NAS.

Both modes can be used simultaneously. They are independent configurations.

> **Link2NAS does not replace Prowlarr.** It does not manage indexers, does not index torrent sites, and does not replace any Prowlarr functionality. It queries Prowlarr's API on your behalf. You still need a running, configured Prowlarr instance.

---

## Prerequisites

### For Mode A (send from Prowlarr)

- A running Prowlarr instance.
- A Link2NAS API key with the `qbittorrent:write` scope (created in **Settings > API Keys**).
- Network connectivity from Prowlarr to Link2NAS.

### For Mode B (native search)

All of the above, plus:

- At least one active indexer configured and tested in Prowlarr.
- A Prowlarr API key.
- The Prowlarr base URL must be reachable from Link2NAS (e.g. from within the Docker network if both are containerised).

Indexers are configured and tested in Prowlarr — not in Link2NAS. Link2NAS does not manage Prowlarr indexers.

---

## Mode A — Send from Prowlarr

### Step 1 — Create a Link2NAS API key

1. Log in to Link2NAS as the user that will receive Prowlarr submissions.
2. Go to **Settings > API Keys**.
3. Create a new key with the scope **`qbittorrent:write`**.
4. **Copy the key immediately** — it is displayed only once.

### Step 2 — Configure Prowlarr

In Prowlarr, go to **Settings > Download Clients > Add Download Client** and select **qBittorrent**.

| Field | Value |
|---|---|
| **Name** | Link2NAS (or any label) |
| **Host** | Your Link2NAS hostname or IP |
| **Port** | Port of your Link2NAS instance (or reverse proxy) |
| **Username** | Any value — not checked by Link2NAS |
| **Password** | Your Link2NAS API key (the one created above) |
| **Category** | Optional — accepted but not used for routing |
| **Use SSL** | Enable if Link2NAS is behind HTTPS |

Click **Test** to verify connectivity, then **Save**.

### How it works

The qBittorrent-compatible layer is mounted at `/qbittorrent/api/v2/`.

Authentication is read from the `password` form field (used by Prowlarr's login flow) or the `X-Api-Key` header. The `username` field is ignored — the API key alone determines the user.

Accepted inputs on `POST /qbittorrent/api/v2/torrents/add`:

- **Magnet links** via the `urls` form field
- **`.torrent` file uploads** via multipart form data

When Prowlarr submits a torrent, Link2NAS creates a standard job using the submitting user's **default provider** (RealDebrid or AllDebrid) and their **default destination** if configured — otherwise it falls back to links-only.

The endpoint returns `Ok.` on success (standard qBittorrent response). Errors from the debrid provider are propagated as appropriate HTTP responses.

### What Mode A does not do

- Link2NAS is not a full qBittorrent client.
- No seeding, ratio tracking, or peer management.
- No pause/resume of individual torrent pieces.
- No per-category routing to different destinations.
- No qBittorrent WebUI — only the endpoints required for remote add are implemented.

---

## Mode B — Native search in Link2NAS

The native search page (`/prowlarr`) lets you search Prowlarr indexers from within Link2NAS and add results as jobs without leaving the interface.

### Configuration

Native search requires a Prowlarr URL and API key stored in Link2NAS. Two levels of configuration are available:

#### Global configuration (Admin)

Configured by a super admin in **Admin > Prowlarr**. Applies to all users who have not set their own configuration.

#### Per-user configuration (Settings)

Configured individually in **Settings > Prowlarr**. Takes priority over the global configuration for that user.

#### Priority

| Condition | Effective source |
|---|---|
| User has a personal configuration enabled | User configuration |
| No personal configuration, global exists and is enabled | Global configuration |
| Neither configured | Prowlarr unavailable |

The connection banner on the search page shows which source is active.

#### What is stored

- Prowlarr base URL.
- Prowlarr API key — **encrypted at rest** using the backend encryption key. Never returned in plain text after saving. Never exposed to the frontend.
- Login credentials for the Prowlarr web interface are **not stored** — Link2NAS only communicates with Prowlarr via its API.

### Search

The search form provides the following controls.

#### Free-text query

Type any search term. Leave blank only when a period limiter is active (see below).

#### Period filter

Filters results by publish date, applied client-side after receiving Prowlarr's results.

| Value | Behaviour |
|---|---|
| **Today** | Results published since midnight (local time) |
| **Last 7 days** | Results from the last 7 days |
| **Last 30 days** | Results from the last 30 days |
| **All dates** | No date restriction |

> **Rule:** A search without a query term is only allowed when the period is set to **Today**, **Last 7 days**, or **Last 30 days**. The **All dates** period requires a query term. This prevents unbounded open searches.

#### Category filter

Optionally narrow results to one or more Prowlarr/Newznab categories (Movies, TV, Audio, PC, Books). If no category is selected, all categories are searched.

#### Indexer filter

Optionally restrict the search to specific active indexers. If no indexer is selected, all available indexers are queried.

> **Note:** Selecting categories or indexers without a query term does **not** bypass the period requirement. The period is still required when the query is empty.

#### Sort

Results are sorted **newest first** by default. Click any column header to sort by that column. Click again to reverse direction.

Sortable columns: **Title**, **Age**, **Indexer**, **Size**, **Seeders**.

Columns for Size, Seeders, and Age default to descending order on first click (largest / most / newest first). Title and Indexer default to ascending.

#### Pagination

Searches use server-side pagination via Prowlarr's `limit` and `offset` parameters.

| Setting | Value |
|---|---|
| **Page size options** | 10 / 25 / 50 |
| **Default page size** | 25 |
| **Previous** | Disabled on the first page |
| **Next** | Active when the current page returned a full page of results |

Changing any filter or the page size resets the page to 0.

### Result table

| Column | Description |
|---|---|
| **Title** | Release title |
| **Age** | Time since publish date (e.g. `2h`, `3d`, `1y`) |
| **Indexer** | Source indexer name |
| **Size** | Release size |
| **Seeders** | Seeder count |
| **Links** | Availability badges: **Magnet**, **Torrent**, **Info** |
| **Add** | Creates a job from this result |

The **Magnet** badge indicates a genuine `magnet:?` URI is available (resolved server-side). The **Torrent** badge indicates an HTTP(S) `.torrent` download URL is available. HTTPS redirect URLs that masquerade as magnets are not flagged as Magnet.

Clicking **Add & start** creates a job using the result's cached `result_id`. The job is started immediately. Sensitive URLs are never sent to the browser.

### Saved searches

Searches can be saved to browser `localStorage` with a custom name.

A saved search stores:

- Search name
- Query text
- Period
- Selected categories
- Selected indexers
- Sort field and direction

Saved searches are local to the browser. They are not stored server-side or in the database. Clearing browser storage removes them.

---

## Security

- The frontend never receives `download_url`, `magnet_url`, `info_url`, API keys, tokens, or passkeys.
- The frontend interacts exclusively with temporary `result_id` identifiers.
- Sensitive URLs are stored only in the backend result cache (TTL: 20 minutes). The cache is user-isolated.
- Link2NAS resolves a usable source server-side before creating a job:
  - **Real magnet URI** — looked up in `magnet_url`, `download_url`, and `guid` (in that order). The first `magnet:?` URI wins.
  - **HTTP(S) torrent URL** — `download_url` only, when it is an HTTP(S) URL pointing to a `.torrent` file.
- When the usable source is a `.torrent` URL, Link2NAS fetches the file server-side and never exposes the URL to the debrid provider or the browser.
- Backend logs do not contain Prowlarr URLs, magnet full content, passkeys, or tokens.
- The Prowlarr API key is encrypted at rest. Never logged. Never returned by the API after saving.

---

## Troubleshooting

### Mode A

| Symptom | Likely cause |
|---|---|
| Prowlarr test returns "Unauthorized" | API key is incorrect, missing, or the scope is not `qbittorrent:write` |
| Prowlarr test passes but jobs are not created | The user has no default provider configured in Settings |
| Jobs are created but fail immediately | Provider rejected the torrent — check the job error message |
| Jobs created but local destination is pending | The local-download worker is not running (see [INSTALL.md](INSTALL.md#run-workers)) |
| Prowlarr cannot reach Link2NAS | Check the host, port, and SSL settings; verify that Link2NAS is accessible from the Prowlarr host |

### Mode B — Native search

| Symptom | Likely cause |
|---|---|
| "Prowlarr is not configured" on the search page | No active Prowlarr URL and API key in Settings or Admin |
| Connection banner shows an error | Prowlarr is unreachable or the API key is invalid — test the connection from Settings > Prowlarr |
| Indexer list is empty | Prowlarr has no active indexers, or the API key lacks permission to list them |
| Search returns no results | No results matched the query in Prowlarr — try a different term or period |
| "Add & start" button is greyed out | The result has neither a real magnet URI nor an HTTP(S) torrent URL |
| Job creation fails with "Result not found or has expired" | The result cache TTL (20 minutes) has elapsed — run the search again |
| Prowlarr is not reachable from Docker Link2NAS | Use the container name or internal Docker network address, not `localhost` |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for additional diagnostic steps.

---

## Related documentation

| Document | Content |
|---|---|
| [QBITTORRENT_COMPATIBILITY.md](QBITTORRENT_COMPATIBILITY.md) | Technical scope and limitations of the qBittorrent compatibility endpoint |
| [SECURITY.md](SECURITY.md) | API key security model, secret handling, encryption |
| [CONFIGURATION.md](CONFIGURATION.md) | All environment variables, including `V2_SECRET_ENCRYPTION_KEY` |
| [INSTALL.md](INSTALL.md) | Initial installation and worker setup |
