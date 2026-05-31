import type {
  NotificationRule,
  NotificationEvent,
  NotificationChannel,
} from './notifications.types'

export const MOCK_SUMMARY = {
  enabledRules: 5,
  eventsToday: 12,
  failedDeliveries: 1,
  pending: 2,
}

export const MOCK_RULES: NotificationRule[] = [
  { id: 'r1', event: 'Job completed', eventType: 'job_completed', channel: 'email', target: 'admin@maison.local', enabled: true, lastTriggered: '29/05/2026 10:12' },
  { id: 'r2', event: 'Job failed', eventType: 'job_failed', channel: 'email', target: 'admin@maison.local', enabled: true, lastTriggered: '28/05/2026 19:17' },
  { id: 'r3', event: 'Download ready', eventType: 'download_ready', channel: 'gotify', target: 'nas.local:8080', enabled: true, lastTriggered: '29/05/2026 09:54' },
  { id: 'r4', event: 'Job started', eventType: 'job_started', channel: 'in-app', target: 'In-app only', enabled: true, lastTriggered: '29/05/2026 08:32' },
  { id: 'r5', event: 'Provider error', eventType: 'provider_failed', channel: 'email', target: 'admin@maison.local', enabled: true, lastTriggered: null },
  { id: 'r6', event: 'Job completed', eventType: 'job_completed', channel: 'webhook', target: 'http://nas.local/hooks/l2n', enabled: false, lastTriggered: '25/05/2026 14:00' },
]

export const MOCK_EVENTS: NotificationEvent[] = [
  { id: 'e1', eventType: 'job_completed', title: 'Job completed', detail: 'Film.Example.2024.1080p.BluRay', channel: 'email', delivered: true, read: true, timestamp: '29/05/2026 10:12' },
  { id: 'e2', eventType: 'download_ready', title: 'Download ready', detail: 'Serie.Example.S03E01-S03', channel: 'gotify', delivered: true, read: false, timestamp: '29/05/2026 09:54' },
  { id: 'e3', eventType: 'job_started', title: 'Job started', detail: 'Show.Example.S04E01-S04E10.HDTV', channel: 'in-app', delivered: true, read: false, timestamp: '29/05/2026 08:32' },
  { id: 'e4', eventType: 'job_failed', title: 'Job failed', detail: 'Film.DV.Example.2160p.DDP5.1.Atmos — provider unreachable', channel: 'email', delivered: false, read: false, timestamp: '28/05/2026 19:17' },
  { id: 'e5', eventType: 'job_completed', title: 'Job completed', detail: 'Documentary.Example.4K.HDR.BluRay', channel: 'email', delivered: true, read: true, timestamp: '28/05/2026 22:01' },
  { id: 'e6', eventType: 'system_warning', title: 'Disk space low', detail: 'NAS Maison — 91 % used', channel: 'in-app', delivered: true, read: true, timestamp: '28/05/2026 18:00' },
]

export const MOCK_CHANNELS: NotificationChannel[] = [
  { id: 'email', name: 'Email', description: 'SMTP email delivery', configured: true, target: 'admin@maison.local' },
  { id: 'gotify', name: 'Gotify', description: 'Push via self-hosted Gotify server', configured: true, target: 'nas.local:8080' },
  { id: 'webhook', name: 'Webhook', description: 'HTTP POST to a custom URL', configured: false, target: null },
  { id: 'in-app', name: 'In-app', description: 'Shown in the Link2NAS UI only', configured: true, target: null },
]
