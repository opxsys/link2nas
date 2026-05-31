# Link2NAS - Claude Project Instructions

## Project context

Link2NAS is a self-hosted Flask application for creating download jobs from magnet links, torrent files, direct links, and Prowlarr/qBittorrent-compatible submissions.

Link2NAS 3.0.0.0 is stable.

The current legacy UI is stable and must remain available.

## Current goal

Build a new optional frontend served under `/next`.

The new frontend must:
- use React + Vite + TypeScript
- use Tailwind CSS
- use shadcn/ui components
- keep the current legacy UI intact
- consume the existing backend APIs
- avoid backend business changes unless strictly required
- be served as static files by Flask under `/next`
- use light mode as the default theme
- support dark mode, high contrast mode, and colorblind-friendly visual status indicators
- include a collapsible sidebar
- be desktop-first and responsive enough for mobile

## Do not do

- Do not replace the existing UI.
- Do not remove legacy frontend files.
- Do not rename existing API endpoints.
- Do not modify provider/destination/job business logic unless explicitly requested.
- Do not introduce Next.js.
- Do not add heavy dependencies unless justified.
- Do not log or expose secrets.
- Do not touch production secrets or real `.env` values.
- Do not perform large refactors during the first implementation step.

## Next UI reference

For the Link2NAS v3.1 Next UI work, read:

- `docs/ui-next/design-spec.md`

Visual references are stored in:

- `docs/ui-next/mockups/00-dark-reference-collage.jpeg`
- `docs/ui-next/mockups/01-dashboard-light.png`
- `docs/ui-next/mockups/02-jobs-detail-light.jpeg`
- `docs/ui-next/mockups/03-accessibility-settings-light.jpeg`

These images are references, not strict pixel-perfect requirements.

The goal is to reproduce the general product feel:
- clean light UI by default;
- collapsible sidebar;
- clear cards;
- readable tables;
- status badges with icons and text;
- accessible themes;
- self-hosted admin-product style.

## Preferred pages

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

## UI style

The UI should feel like a clean self-hosted admin product:
- Portainer / Proxmox / Grafana inspired
- sober
- readable
- not flashy
- light theme first
- strong accessibility
- clear status badges with icons and text, not color only

## Development rules

Work in small steps.

Before important modifications:
- explain the plan;
- list files likely to be changed;
- avoid broad refactors.

After each step, explain:
- files changed;
- commands to run;
- how to test;
- risks.

## First implementation target

The first implementation should only create the `/next` shell:

- `frontend-next/`
- React + Vite + TypeScript
- Tailwind CSS
- shadcn/ui
- AppShell
- collapsible sidebar
- header
- route/pages placeholders
- light theme default
- theme/accessibility foundation
- Flask route/static serving for `/next`

Do not migrate Jobs, Settings, Admin, or provider/destination logic in the first step.

## Code size and file structure rules

Avoid large files.

Preferred limits:
- React page files should stay under ~250 lines when possible.
- Shared components should stay focused and small.
- If a page grows, split it into subcomponents.
- If logic grows, extract hooks or helper modules.
- If API calls grow, create dedicated files under `src/api/`.
- If status/theme/mapping logic grows, extract it under `src/lib/`.

Do not create monolithic files such as:
- one huge `App.tsx`;
- one huge `JobsPage.tsx`;
- one huge `SettingsPage.tsx`;
- one huge `api.ts`;
- one huge `components.tsx`.

Preferred structure:
- `src/pages/<PageName>/index.tsx`
- `src/pages/<PageName>/<SubComponent>.tsx`
- `src/pages/<PageName>/<pageName>.types.ts`
- `src/pages/<PageName>/<pageName>.utils.ts`
- `src/api/<domain>.ts`
- `src/components/common/*`
- `src/components/layout/*`
- `src/components/status/*`

When implementing a complex page, first create a small page container, then move sections into dedicated components.

Before adding more than ~250 lines to a file, stop and split it.
