/** Canonical job status values matching the backend status field. */
export type JobStatus =
  | 'created'
  | 'waiting'
  | 'running'
  | 'downloading'
  | 'ready'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'sending'
  | 'sent'
  | 'links_only'

/** Operational health status for system services and directory checks. */
export type HealthStatus = 'ok' | 'warning' | 'error' | 'unknown'
