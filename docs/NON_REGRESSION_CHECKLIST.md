# Non-Regression Checklist

Manual checklist for pre-release validation of Link2NAS. Run before merging a large change or publishing a release.

This is not exhaustive QA. The goal is to catch regressions in critical flows before they reach users.

---

## Authentication / Session

- [ ] Login with valid credentials returns a session token
- [ ] Login with invalid credentials returns 401
- [ ] Logout revokes the current session token server-side: after logout, using the same `X-Api-Key` returns `{"error": "Invalid API key"}`
- [ ] Logout is idempotent: calling logout twice with the same token returns 200 both times (no 500)
- [ ] Logout with no `X-Api-Key` returns 200 (no crash)
- [ ] User API Keys created in Settings > API Keys are **not** revoked by logout — they remain valid
- [ ] Magic login flow creates a session token that is also revoked by logout

---

## A. Jobs

- [ ] Jobs list loads and displays correctly
- [ ] Job detail page opens with correct metadata
- [ ] Start action works on a created job
- [ ] Refresh action updates job status
- [ ] Restart action works on a failed or cancelled job
- [ ] Cancel action works on an active job
- [ ] Delete action removes the job
- [ ] Multi-file torrent: file selection UI opens, individual files selectable, selection saved
- [ ] Direct link job: link unrestricted and result displayed
- [ ] Copy link button works on a completed job
- [ ] Copy all links button works on a multi-link job
- [ ] Resend destination works on a completed job (links re-sent to destination)
- [ ] Failed job state displayed clearly with error message
- [ ] Completed job shows result links
- [ ] Links-only job shows links without requiring a destination

---

## B. New Job

- [ ] Magnet link submission creates a job
- [ ] Direct link submission creates a job
- [ ] Single `.torrent` file upload creates a job
- [ ] Batch upload of multiple `.torrent` files creates one job per file
- [ ] Provider selection works (selects the correct configured provider)
- [ ] Destination selection works (sends to the chosen destination)
- [ ] Links-only mode creates a job without requiring a destination
- [ ] Upload error for an invalid file shows a clear per-file message, not a generic crash
- [ ] Batch result (success/error per file) is displayed correctly
- [ ] With no provider configured: New Job form is blocked or redirected with a clear message

---

## C. Settings

- [ ] Account profile saves correctly (display name, language, theme)
- [ ] Language selector changes the UI language immediately
- [ ] Theme selector changes the theme immediately and persists
- [ ] Provider profile: create, save, and list
- [ ] Provider profile: edit and save changes
- [ ] Provider API key: test connection returns user info
- [ ] Provider profile: enable and disable
- [ ] Provider profile: set as default
- [ ] Destination profile: create, save, and list
- [ ] Destination profile: edit and save changes
- [ ] Destination profile: test connection
- [ ] Destination profile: enable and disable
- [ ] Destination profile: set as default
- [ ] API key: create, secret shown once only
- [ ] API key: revoke works
- [ ] API key: delete works
- [ ] Prowlarr URL and API key save correctly
- [ ] Notification channel (email, Gotify, or webhook) create and save
- [ ] Notification rule: create with severity threshold
- [ ] **"Receive application emails" / "Recevoir les e-mails d'annonces applicatives":**
  - [ ] Checkbox saves correctly
  - [ ] When unchecked, announcement emails are not sent to the user
  - [ ] Transactional/authentication emails (invitation, password reset, magic login, email verification) are unaffected by this setting — they continue regardless

---

## D. Admin

- [ ] Admin Overview loads with system info
- [ ] Admin General: app name and tagline update via the form
- [ ] Admin Users: user list loads
- [ ] Admin Users: create a new user account
- [ ] Admin Users: edit a user (change role, disable/enable)
- [ ] Admin Users: delete a user
- [ ] Admin Users: generate invitation link (copyable even if SMTP is off)
- [ ] Admin Users: generate password reset link (copyable even if SMTP is off)
- [ ] Admin SMTP: SMTP settings form saves
- [ ] Admin SMTP: warning displayed when SMTP is disabled or not configured
- [ ] Admin SMTP: test email sends when SMTP is configured
- [ ] Admin Announcements: create an announcement
- [ ] Admin Announcements: publish and unpublish an announcement
- [ ] Admin Announcements: tracking view shows opens/reads/acknowledges
- [ ] Admin Announcements: global enable/disable toggle works
- [ ] Admin Email Templates: preview renders without error
- [ ] Admin Email Templates: reset to default works
- [ ] Admin Security: anti-abuse counter reset works
- [ ] Admin Timeouts: timeout values save correctly
- [ ] Admin Runtime: runtime settings save correctly
- [ ] Admin Runtime: test notification sends
- [ ] Admin Cleanup: cleanup settings save and manual cleanup runs
- [ ] Admin System Events: event list loads
- [ ] Admin Maintenance: information displayed correctly

---

## E. Announcements / Banner / Tracking

- [ ] Global announcements enabled: announcements visible to users
- [ ] Global announcements disabled: banner hidden, announcements page shows no announcements (existing records preserved)
- [ ] Published announcement appears on the user announcements page
- [ ] Announcement banner visible on page load when there is an unread announcement
- [ ] Mark as read works (banner dismisses, announcement marked read)
- [ ] Acknowledge action works and is recorded in tracking
- [ ] Dismiss banner works (banner hides for the session)
- [ ] Admin tracking page shows correct counts for opens, reads, acknowledges
- [ ] Announcement email sent only when SMTP is enabled AND user has opted in to application announcement emails
- [ ] User who opted out does not receive announcement email, but still sees the announcement in the UI

---

## F. Prowlarr / qBittorrent Compatibility

- [ ] Prowlarr tab is visible in Settings when Prowlarr is configured
- [ ] Prowlarr iframe or new-tab fallback loads without error
- [ ] qBittorrent compatibility endpoint: `GET /qbittorrent/api/v2/app/version` returns a version string
- [ ] API key with `qbittorrent:write` scope created and works for qBittorrent auth
- [ ] Prowlarr sends a magnet via the qBittorrent endpoint → job created in Link2NAS
- [ ] Prowlarr sends a `.torrent` file via multipart upload → job created
- [ ] Category field in the submission is accepted and ignored safely (no error)
- [ ] Job created by Prowlarr uses the user's default provider and destination (or links-only if no destination)

---

## G. Notifications

- [ ] User notification channel (email): create and test
- [ ] User notification channel (Gotify): create and test
- [ ] User notification channel (webhook): create and test
- [ ] Notification rule: create with event type and severity threshold
- [ ] Event timeline loads for the user
- [ ] Test notification from Admin > Runtime reaches configured channels
- [ ] When SMTP is not configured: email channel warning displayed, no crash
- [ ] System notifications visible to super admin only
- [ ] Notification dispatcher can be enabled/disabled from Admin > Runtime

---

## H. Single-User / Multi-User

- [ ] Single-user mode: app starts with a fixed account, no registration required
- [ ] Single-user mode: `LINK2NAS_SINGLE_USER_EMAIL` and `LINK2NAS_SINGLE_USER_DISPLAY_NAME` respected
- [ ] Multi-user mode: login page appears, registration or invitation flow works
- [ ] Super admin can access Admin section
- [ ] Normal user cannot access Admin section (receives 403 or redirect)
- [ ] Disabled account cannot log in
- [ ] Expired account behavior is handled cleanly (if applicable)
- [ ] Session inactivity timeout works if configured

---

## I. SMTP On/Off

- [ ] SMTP enabled: test email sends from Admin > SMTP
- [ ] SMTP disabled: email-related UI warnings shown where applicable (announcements, notifications)
- [ ] SMTP disabled: invitation links are still copyable manually
- [ ] SMTP disabled: password reset links are still copyable manually
- [ ] SMTP disabled: announcement emails are not sent
- [ ] Transactional/authentication emails (password reset, invitation, email verification, magic login) remain separate from the "Receive application emails" preference — they are triggered by user actions, not by admin broadcast

---

## J. Mobile

- [ ] Sidebar drawer opens from the hamburger button
- [ ] Sidebar drawer closes with the close button or outside click
- [ ] Close button is focusable and activatable via keyboard
- [ ] Hamburger button aria-expanded state is correct (true/false)
- [ ] Long app name is truncated cleanly in the header
- [ ] Jobs, New Job, Settings pages are usable on a narrow viewport
- [ ] Admin nav is accessible on mobile

---

## K. Theme / Accessibility

- [ ] Light theme: default, readable
- [ ] Dark / night theme: switch works, persists after reload
- [ ] High contrast theme (if configured): visible and readable
- [ ] Colorblind-friendly indicators: status badges show icon + text, not color alone
- [ ] Theme selection persists across sessions
- [ ] Theme change applies immediately without page reload
- [ ] No obviously unreadable text contrast in any supported theme
- [ ] Keyboard navigation reaches interactive elements (buttons, links, selects)
- [ ] Focus outlines visible on keyboard navigation

---

## L. Home Page / Navigation

- [ ] App name / logo click routes to the configured home page
- [ ] Default home page is accessible after login
- [ ] Prowlarr disabled or unavailable: navigation falls back without crash
- [ ] `/next/` loads the Next UI
- [ ] `/` redirects or serves the appropriate default interface
- [ ] Public token routes (`/invite`, `/verify-email`, `/reset-password`, `/magic-login`) render in the Next UI
- [ ] Invalid or expired token routes show a clear error message before displaying the form

---

## M. Runtime / Docker / PostgreSQL

- [ ] Fresh SQLite install: app starts, setup page appears, first admin can be created
- [ ] Fresh PostgreSQL install: app starts, schema applied automatically, same flow
- [ ] Redis is running: worker processes connect without error
- [ ] `worker.py` running: debrid jobs are processed
- [ ] `scheduler` running: scheduled tasks execute without error
- [ ] `local-download-worker` running: local download jobs are processed
- [ ] `WEB_CONCURRENCY=1`: web container starts with exactly 1 gunicorn worker
- [ ] Health endpoint: `GET /health` returns `{"ok": true}` with HTTP 200
- [ ] Application logs show no unexpected stacktrace on startup
- [ ] Docker Compose: all containers reach `running` or `healthy` state within the expected time

---

## N. Version / Release Metadata

- [ ] App version is displayed in Admin > Maintenance (or equivalent) when `APP_VERSION` is set
- [ ] `APP_VERSION=unknown` is shown when not injected (expected for dev builds)
- [ ] No inconsistent or outdated version strings found in README or docs
- [ ] GHCR image tag is documented correctly (`ghcr.io/opxsys/link2nas:<TAG>`)
- [ ] **Version-from-CI item tracked:** `APP_VERSION` should be injected from the GitHub release tag or CI pipeline. This is not yet automated — see [BACKLOG.md](BACKLOG.md).
