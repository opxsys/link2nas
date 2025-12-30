# Link2NAS – Chrome Extension

Chrome extension for **Link2NAS** that lets you send links and magnets directly to your Link2NAS backend (AllDebrid → NAS).

This extension is intentionally **decoupled** from the backend and is **not served by Flask**.

---

## Features

- Send download links to Link2NAS in one click
- Detect magnet links and supported URLs
- Background service worker (Manifest V3)
- Options page to configure backend URL
- Lightweight, no external dependencies

---

## Directory structure

```
extensions/chrome/
├── manifest.json
├── service_worker.js
├── content_script.js
├── options.html
├── options.js
├── icon16.png
├── icon48.png
└── icon128.png
```

---

## Requirements

- Google Chrome (or Chromium-based browser)
- A running Link2NAS backend (default: `http://localhost:5000`)

---

## Installation (Developer mode)

1. Open Chrome and go to:
   ```
   chrome://extensions
   ```

2. Enable **Developer mode** (top-right)

3. Click **Load unpacked**

4. Select the folder:
   ```
   extensions/chrome
   ```

5. The Link2NAS extension should now appear in your toolbar

---

## Configuration

1. Open the extension options
2. Set the **Link2NAS backend URL**, for example:
   ```
   http://localhost:5000
   ```
3. Save

---

## Security notes

- No credentials are stored in the extension
- Authentication is handled by the backend (Basic Auth if enabled)
- No analytics, no tracking, no third-party calls

---

## Development notes

- Manifest version: **V3**
- Background logic runs in `service_worker.js`
- Page interaction handled by `content_script.js`

---

## License

Same license as the main Link2NAS project.
