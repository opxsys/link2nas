import type { RealJob } from '@/api/jobs'

// Re-export for component convenience
export type { RealJob, RealJobFile } from '@/api/jobs'

export interface JobsFilters {
  search: string
  status: string
  provider: string
  destination: string
}

/** Display name for a job: prefer filename, fall back to source_value. */
export function jobName(job: RealJob): string {
  return job.filename || job.source_value || job.id
}

/** Display label for a job's provider. */
export function jobProvider(job: RealJob): string {
  return job.provider_profile_name || job.provider_name || job.provider_type || '—'
}

/** Display label for a job's destination; null → links only. */
export function jobDestination(job: RealJob): string | null {
  return job.destination_profile_name || job.destination_name || null
}

/** Progress shape used by JobProgressCard. */
export interface JobProgress {
  percent: number | null
  downloadedSize: string | null
  speed: string | null
  eta: string | null
  connections: number | null
  provider: string | null
}

/** Format bytes to human-readable string. */
export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}
