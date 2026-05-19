# Prowlarr Integration

## Purpose

Link2NAS exposes a minimal qBittorrent-compatible API endpoint that allows Prowlarr (and other tools that support qBittorrent as a download client) to send magnets and `.torrent` files directly to Link2NAS.

When Prowlarr submits a torrent, Link2NAS creates a standard job using the user's default provider and default destination.

---

## What it does

- Prowlarr sends a magnet link or `.torrent` file via the qBittorrent API
- Link2NAS creates a job and starts it using the submitting user's **default provider** (RealDebrid or AllDebrid)
- The job is sent to the user's **default destination** if one is configured, otherwise it falls back to links-only
- The `category` field sent by Prowlarr is accepted and stored on the submission record, but is not used for destination routing

---

## What it does not do

- Link2NAS is not a full qBittorrent client
- No seeding, ratio tracking, or peer management
- No pause/resume of individual torrent pieces
- No per-category routing to different destinations
- No qBittorrent WebUI — only the API endpoints required for remote add are implemented

---

## Step 1 — Create a Link2NAS API key

1. Log in to Link2NAS as the user that will receive Prowlarr submissions
2. Go to **Settings > API Keys**
3. Create a new key with the scope **`qbittorrent:write`**
4. **Copy the key immediately** — it is displayed only once

---

## Step 2 — Configure Prowlarr

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

---

## How the endpoint works

The qBittorrent-compatible layer is mounted at `/qbittorrent/api/v2/`.

Authentication is read from the `password` form field (used by Prowlarr's login flow) or the `X-Api-Key` header. The `username` field is ignored entirely — the API key alone determines the user.

Accepted inputs on `POST /qbittorrent/api/v2/torrents/add`:
- **Magnet links** via the `urls` form field
- **`.torrent` file uploads** via multipart form data

The endpoint returns `Ok.` on success (standard qBittorrent response). Errors from the debrid provider are propagated as appropriate HTTP responses.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Prowlarr test returns "Unauthorized" | API key is incorrect, missing, or the scope is not `qbittorrent:write` |
| Prowlarr test passes but jobs are not created | The user has no default provider configured in Settings |
| Jobs are created but fail immediately | Provider rejected the torrent — check the job error message |
| Jobs created but local destination is pending | The local-download worker is not running (see [INSTALL.md](INSTALL.md#run-workers)) |
| Prowlarr cannot reach Link2NAS | Check the host, port, and SSL settings; verify that Link2NAS is accessible from the Prowlarr host |

---

## Security

- Create a dedicated API key for Prowlarr — do not reuse your admin session token or a key with broader scopes
- Revoke the key immediately from Settings if it is exposed or compromised
- If Prowlarr communicates with Link2NAS over a network (not localhost), use HTTPS
- See [SECURITY.md](SECURITY.md) for the full API key security model
