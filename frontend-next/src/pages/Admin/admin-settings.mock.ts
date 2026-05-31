import type { SmtpConfig, SecurityConfig, RuntimeComponent, RetentionRule } from './admin.types'

export const MOCK_SMTP: SmtpConfig = {
  configured: true,
  provider: 'Self-hosted (Postfix)',
  host: 'smtp.maison.local',
  port: 587,
  from: 'link2nas@maison.local',
  tlsEnabled: true,
}

export const MOCK_SECURITY: SecurityConfig = {
  tokenTtlDays: 30,
  sessionInactivityMinutes: 60,
  passwordMinLength: 12,
  requireUppercase: true,
  requireNumbers: true,
  rateLimitEnabled: true,
  rateLimitPerMinute: 60,
}

export const MOCK_RUNTIME: RuntimeComponent[] = [
  { id: 'scheduler',   name: 'Scheduler',   status: 'running', interval: 'every 30s', description: 'Triggers periodic job checks and maintenance tasks.' },
  { id: 'worker',      name: 'Worker',      status: 'running', interval: 'every 10s', description: 'Processes queued download and transfer jobs.' },
  { id: 'dispatcher',  name: 'Dispatcher',  status: 'running', interval: 'every 15s', description: 'Routes notifications to configured channels.' },
  { id: 'notifier',    name: 'Notifier',    status: 'stopped', interval: null,        description: 'Optional push notifier — requires Gotify or webhook config.' },
]

export const MOCK_RETENTION: RetentionRule[] = [
  { id: 'rt1', target: 'Completed jobs',  retainDays: 90,  lastRun: '28/05/2026 03:00', nextRun: '29/05/2026 03:00' },
  { id: 'rt2', target: 'Failed jobs',     retainDays: 30,  lastRun: '28/05/2026 03:00', nextRun: '29/05/2026 03:00' },
  { id: 'rt3', target: 'Cancelled jobs',  retainDays: 14,  lastRun: '28/05/2026 03:00', nextRun: '29/05/2026 03:00' },
  { id: 'rt4', target: 'System events',   retainDays: 60,  lastRun: '28/05/2026 03:00', nextRun: '29/05/2026 03:00' },
  { id: 'rt5', target: 'Audit logs',      retainDays: 365, lastRun: '28/05/2026 03:00', nextRun: '29/05/2026 03:00' },
]
