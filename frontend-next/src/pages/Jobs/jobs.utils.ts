import type { JobStatus } from '@/lib/types'
import type { Job, JobsFilters } from './jobs.types'

export function displayValue(
  value: string | number | null | undefined,
  fallback = '—',
): string {
  if (value === null || value === undefined || value === '') return fallback
  return String(value)
}

export function filterJobs(jobs: Job[], filters: JobsFilters): Job[] {
  const search = filters.search.trim().toLowerCase()
  return jobs.filter((job) => {
    if (search && !job.name.toLowerCase().includes(search)) return false
    if (filters.status && job.status !== (filters.status as JobStatus)) return false
    if (filters.provider && job.provider !== filters.provider) return false
    if (filters.destination && (job.destination ?? '') !== filters.destination) return false
    return true
  })
}

export function getUniqueProviders(jobs: Job[]): string[] {
  return [...new Set(jobs.map((j) => j.provider))].sort()
}

export function getUniqueDestinations(jobs: Job[]): string[] {
  return [...new Set(jobs.flatMap((j) => (j.destination ? [j.destination] : [])))].sort()
}

export const JOB_STATUS_OPTIONS: { value: JobStatus; label: string }[] = [
  { value: 'created', label: 'Created' },
  { value: 'waiting', label: 'Waiting' },
  { value: 'running', label: 'Running' },
  { value: 'downloading', label: 'Downloading' },
  { value: 'ready', label: 'Ready' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'cancelled', label: 'Cancelled' },
  { value: 'sending', label: 'Sending' },
  { value: 'sent', label: 'Sent' },
  { value: 'links_only', label: 'Links only' },
]
