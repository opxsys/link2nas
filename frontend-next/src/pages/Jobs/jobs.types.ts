import type { RealJob } from '@/api/jobs'

// Re-export for component convenience
export type { RealJob, RealJobFile } from '@/api/jobs'

export interface JobsFilters {
  search: string
  status: string
  provider: string
  destination: string
}

/** Display name for a job: prefer filename, then safe fallbacks by source type. */
export function jobName(job: RealJob): string {
  if (job.filename) return job.filename
  // For magnet jobs try to extract the human-readable &dn= fragment.
  // Raw magnet URLs (or Prowlarr redirect URLs) must never be shown directly.
  if (job.source_type === 'magnet') {
    return _magnetDisplayName(job.source_value) ?? job.id
  }
  // For torrent_file, source_value is "torrent:HASH" — not meaningful to show.
  if (job.source_type === 'torrent_file') return job.id
  return job.source_value || job.id
}

function _magnetDisplayName(value: string | null | undefined): string | null {
  if (!value) return null
  const match = value.match(/[?&]dn=([^&]+)/)
  if (!match) return null
  try { return decodeURIComponent(match[1].replace(/\+/g, ' ')) } catch { return null }
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
