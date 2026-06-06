> **Historical design document.** This file describes the initial Next UI design direction. The Next UI is now the primary interface; use [README.md](../../README.md), [RELEASE_NOTES.md](../RELEASE_NOTES.md), and [NON_REGRESSION_CHECKLIST.md](../NON_REGRESSION_CHECKLIST.md) for current release validation.

# Link2NAS Next UI Design Specification

## Purpose

Link2NAS v3.1 introduces a new optional user interface served under `/next`.

The existing stable UI must remain available and untouched. The new UI is a separate frontend intended to modernize the product experience while reusing the existing Flask backend APIs.

## Visual references

Mockups are stored in:

- `docs/ui-next/mockups/00-dark-reference-collage.png`
- `docs/ui-next/mockups/01-dashboard-light.png`
- `docs/ui-next/mockups/02-jobs-detail-light.png`
- `docs/ui-next/mockups/03-accessibility-settings-light.png`

These images are visual references, not pixel-perfect requirements.

The implementation should reproduce the general feel:

- clean admin/self-hosted product interface;
- light theme as default;
- collapsible sidebar;
- clear page hierarchy;
- modern cards;
- readable tables;
- status badges with icon + text;
- accessible colors;
- dark mode as an optional theme;
- high contrast mode;
- colorblind-friendly status representation.

## Product direction

The UI should feel like a serious self-hosted administration tool, inspired by products such as Portainer, Proxmox, Grafana, and modern storage/admin dashboards.

The UI must not feel like a flashy consumer app. It should be sober, readable, predictable, and efficient.

## Technical stack

Target stack:

- React
- Vite
- TypeScript
- Tailwind CSS
- shadcn/ui
- lucide-react icons

Do not use Next.js.

The new frontend should live in:

```text
frontend-next/
```

The built frontend should be served by Flask under:

```text
/next
```

The legacy frontend must stay available.

## Routing

Initial pages:

- Dashboard
- Jobs
- New Job
- Providers
- Destinations
- Prowlarr
- Notifications
- Settings
- Admin
- Maintenance

The routing can be client-side. Use a simple and maintainable routing setup.

## Layout

The application shell must include:

- left sidebar;
- collapsible sidebar state;
- top header;
- main content area;
- page title and subtitle;
- user/account area;
- theme/accessibility selector;
- logout action;
- responsive behavior for smaller screens.

### Sidebar

The sidebar must support two modes:

1. Expanded mode:
   - Link2NAS logo/name visible;
   - icon + label for each navigation item;
   - user block at the bottom.

2. Collapsed mode:
   - compact width;
   - icons only;
   - tooltips or accessible labels;
   - active route still clearly visible.

The collapsed state should persist in localStorage.

## Themes

The default theme must be Light.

Supported visual modes:

- Light
- Dark
- High Contrast
- Colorblind-friendly

Theme preference should persist in localStorage.

### Light theme

Main target theme.

Expected feel:

- white or near-white background;
- soft grey page background;
- white cards;
- subtle borders;
- blue primary accent;
- readable dark text;
- clear table separators;
- light shadows only when useful.

### Dark theme

Optional theme.

Expected feel:

- dark navy/grey background;
- slightly lighter card surfaces;
- muted borders;
- same layout and spacing as light theme.

Dark mode must not be the visual default.

### High contrast theme

Expected behavior:

- stronger borders;
- stronger text contrast;
- obvious focus outlines;
- statuses readable without relying on subtle color differences.

### Colorblind-friendly mode

Statuses must never rely on color alone.

All statuses must use:

- icon;
- text label;
- shape/badge;
- optional color.

Example:

- Completed: check icon + "Completed"
- Running/Downloading: play/cloud icon + "Downloading"
- Waiting: clock icon + "Waiting"
- Failed: cross/error icon + "Failed"
- Cancelled: minus/ban icon + "Cancelled"
- Pending: timer icon + "Pending"

## Accessibility rules

The new UI must:

- provide visible keyboard focus states;
- not rely on color alone;
- keep sufficient contrast;
- use semantic buttons and form fields;
- expose accessible labels for icon-only buttons;
- use readable font sizes;
- avoid tiny click targets;
- keep destructive actions clearly marked;
- ask confirmation before destructive actions.

## Core components

Create reusable components before implementing full pages.

Recommended components:

- AppShell
- Sidebar
- Header
- PageHeader
- SectionCard
- MetricCard
- StatusBadge
- IconButton
- ActionButton
- DataTable
- EmptyState
- LoadingState
- ErrorState
- ConfirmDialog
- DetailsSheet
- TabsLayout
- FormField
- ThemeSelector
- AccessibilityPreview
- ProgressBlock

Use shadcn/ui where possible.

## Status badges

Status badges are central to the product.

They must be compact but readable.

Each badge must include:

- icon;
- text;
- accessible label;
- color as secondary information.

Suggested statuses:

- Created
- Waiting
- Running
- Downloading
- Ready
- Completed
- Failed
- Cancelled
- Sending
- Sent
- Links only

## Dashboard page

The Dashboard should provide a quick overview of the system.

Sections:

1. Metrics row:
   - Active jobs
   - Completed today
   - Failed today
   - Total jobs

2. System status:
   - Redis
   - Worker
   - Scheduler
   - Database

3. Default configuration:
   - Default provider
   - Default destination
   - Links-only state if no destination is configured

4. Storage:
   - data/jobs usage if available
   - downloads usage if available
   - disk free percentage

5. Recent jobs:
   - name
   - status
   - provider
   - destination
   - created date
   - quick action menu

If an API value is not available yet, display a clean fallback such as "Not available".

## Jobs page

The Jobs page is one of the most important screens.

Expected layout:

- page title and subtitle;
- "New Job" primary action;
- search input;
- status filter;
- provider filter;
- destination filter;
- refresh button;
- jobs table or card/table hybrid.

Columns:

- job name
- status
- provider
- destination
- files
- size
- created
- actions

Rows should be spacious enough to read long names.

Clicking a job should open a details sheet/panel.

## Job details sheet

The job details panel should appear as a right-side sheet.

It should contain:

- job name;
- status badge;
- main actions:
  - Refresh
  - Copy Links
  - Send / Resend when available
  - Cancel / Delete when available
- provider;
- destination;
- files count;
- size;
- created date;
- job ID;
- tabs:
  - Files
  - Links
  - Details
  - Logs

Files tab:

- filename
- size
- status
- link/action icon

Progress block:

- overall progress;
- downloaded size;
- speed if available;
- ETA if available;
- worker count if available;
- connected provider.

Destructive actions must be visually separated and require confirmation.

## New Job page

The New Job page should support:

- Magnet / direct links
- Torrent upload
- Batch upload

Expected layout:

- tabs for input modes;
- textarea for magnet/direct links;
- drag-and-drop zone for torrent upload;
- batch upload result panel;
- provider selector;
- destination selector;
- links-only option when applicable;
- advanced options collapsed by default;
- create button.

After creation, results must be persistent on the page.

Do not use only a transient toast for important batch results.

Batch result should show:

- number of jobs created;
- number of failed items;
- per-file result;
- link to created jobs when possible.

## Settings page

Settings should use a clean tab or side-navigation layout.

Suggested sections:

- General
- Account
- Providers
- Destinations
- Jobs
- Notifications
- Prowlarr
- API Keys
- Accessibility
- System

The Accessibility section should include:

- Light theme
- Dark theme
- High contrast
- Colorblind-friendly
- Focus indicator toggle
- Text size setting if simple
- Preview of badges/buttons/cards/table

## Maintenance page

The Maintenance page should expose operational status clearly.

Sections:

1. System Health:
   - Application
   - Database
   - Redis
   - Disk space
   - Workers/Scheduler if available

2. System Information:
   - version
   - environment
   - Python version if available
   - database backend
   - Redis connection
   - uptime if available

3. Directory checks:
   - data
   - tmp
   - userdata
   - logs
   - torrent temp/internal storage
   - local downloads if configured

4. Actions:
   - Refresh health checks
   - Test SMTP connection if API exists
   - Run cleanup tasks if API exists
   - Process notifications if API exists
   - Restart worker only if actually supported; otherwise do not show it

5. Logs summary:
   - last lines if API exists
   - otherwise clean unavailable state

Do not invent backend APIs without approval. If a minimal endpoint is needed, propose it first.

## Providers and Destinations

These pages/settings should keep the existing Link2NAS logic:

- multiple named provider profiles;
- one active/default provider rule;
- multiple destination profiles;
- zero destination means links-only;
- one active destination can become default automatically;
- multiple active destinations require one default;
- secret fields must never be displayed in clear.

## Prowlarr page

The Prowlarr page should support the existing integration model:

- optional per-user Prowlarr URL;
- iframe when available;
- open in new tab fallback;
- no storage of Prowlarr login/password.

## Notifications page

The Notifications page should show user notification rules and events when available.

For Super Admin, system notifications can be shown separately.

Use readable cards/tables and clear severity badges.

## Admin page

Admin pages must remain protected by existing backend permissions.

Do not expose admin features to normal users.

The frontend should hide admin navigation when the user is not allowed, but backend security remains authoritative.

## Error handling

Errors should be displayed in-page when related to a form or operation.

Use toast notifications only for minor feedback.

Important results such as job creation, batch upload, provider test, destination test, or destructive actions should have persistent feedback.

Error messages should be short, neutral, and professional.

## Internationalization

The first implementation may use English labels internally if needed, but the structure should allow later i18n.

Do not scatter hardcoded text across many files if it can be centralized cleanly.

## Implementation strategy

Work in small steps.

Recommended order:

1. Create `frontend-next`.
2. Add Vite + React + TypeScript + Tailwind + shadcn/ui.
3. Add Flask static serving for `/next`.
4. Create AppShell, sidebar, header, routing, empty pages.
5. Add theme system.
6. Add shared UI components.
7. Implement Dashboard with mock/fallback data first.
8. Implement Maintenance.
9. Implement Jobs read-only.
10. Implement Job details sheet.
11. Implement New Job.
12. Implement Settings sections gradually.

Do not migrate everything at once.

## Non-goals for the first implementation

Do not:

- replace the legacy UI;
- remove legacy frontend files;
- rewrite backend business logic;
- change existing API contracts unnecessarily;
- implement a full design system from scratch when shadcn/ui already provides components;
- add Next.js;
- add heavy dependencies without justification;
- expose secrets;
- break Docker/GHCR deployment.
