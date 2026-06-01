import type { SmtpConfig, RuntimeComponent } from './admin.types'

export const MOCK_SMTP: SmtpConfig = {
  configured: true,
  provider: 'Self-hosted (Postfix)',
  host: 'smtp.maison.local',
  port: 587,
  from: 'link2nas@maison.local',
  tlsEnabled: true,
}

export const MOCK_RUNTIME: RuntimeComponent[] = [
  { id: 'scheduler',   name: 'Scheduler',   status: 'running', interval: 'every 30s', description: 'Triggers periodic job checks and maintenance tasks.' },
  { id: 'worker',      name: 'Worker',      status: 'running', interval: 'every 10s', description: 'Processes queued download and transfer jobs.' },
  { id: 'dispatcher',  name: 'Dispatcher',  status: 'running', interval: 'every 15s', description: 'Routes notifications to configured channels.' },
  { id: 'notifier',    name: 'Notifier',    status: 'stopped', interval: null,        description: 'Optional push notifier — requires Gotify or webhook config.' },
]
