import type { AdminSummary, SystemEventTypeDef, SystemEvent } from './admin.types'

export const MOCK_ADMIN_SUMMARY: AdminSummary = {
  totalUsers: 6,
  activeUsers: 3,
  pendingInvitations: 2,
  systemEventsToday: 3,
}

export const MOCK_SYSTEM_EVENT_TYPES: SystemEventTypeDef[] = [
  { code: 'system.cleanup.failed',              severity: 'error',   deduplicated: true,  rateLimited: false, enabled: true,  description: 'Cleanup task failed to complete.' },
  { code: 'system.maintenance.failed',          severity: 'error',   deduplicated: true,  rateLimited: false, enabled: true,  description: 'Scheduled maintenance task failed.' },
  { code: 'system.smtp.failed',                 severity: 'error',   deduplicated: true,  rateLimited: true,  enabled: true,  description: 'SMTP delivery failure.' },
  { code: 'system.notification_dispatcher.failed', severity: 'warning', deduplicated: true, rateLimited: true, enabled: true, description: 'Notification dispatcher encountered an error.' },
  { code: 'system.scheduler.failed',            severity: 'warning', deduplicated: true,  rateLimited: true,  enabled: true,  description: 'Scheduler failed to run a cycle.' },
  { code: 'system.storage.low',                 severity: 'warning', deduplicated: false, rateLimited: true,  enabled: true,  description: 'Destination storage usage above threshold.' },
]

export const MOCK_SYSTEM_EVENTS: SystemEvent[] = [
  { id: 'se1', code: 'system.storage.low',    severity: 'warning', message: 'NAS Maison — 91 % used (threshold 90 %)',               timestamp: '28/05/2026 18:00', resolved: false },
  { id: 'se2', code: 'system.smtp.failed',    severity: 'error',   message: 'Failed to deliver job completion email — timeout',       timestamp: '28/05/2026 19:20', resolved: true },
  { id: 'se3', code: 'system.scheduler.failed', severity: 'warning', message: 'Scheduler cycle skipped — worker busy',               timestamp: '29/05/2026 07:15', resolved: true },
  { id: 'se4', code: 'system.storage.low',    severity: 'warning', message: 'NAS Maison — 92 % used (threshold 90 %)',               timestamp: '29/05/2026 10:00', resolved: false },
]
