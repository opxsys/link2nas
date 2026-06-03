import type { JobStatus } from '@/lib/types'
import type { RealJob } from '@/api/jobs'
import type { JobsFilters } from './jobs.types'
import { jobName, jobProvider, jobDestination } from './jobs.types'

export { jobName, jobProvider, jobDestination }

export function displayValue(value: string | number | null | undefined, fallback = '—'): string {
  if (value === null || value === undefined || value === '') return fallback
  return String(value)
}

export function filterJobs(jobs: RealJob[], filters: JobsFilters): RealJob[] {
  const search = filters.search.trim().toLowerCase()
  return jobs.filter((job) => {
    if (search && !jobName(job).toLowerCase().includes(search)) return false
    if (filters.status && job.status !== (filters.status as JobStatus)) return false
    if (filters.provider && jobProvider(job) !== filters.provider) return false
    if (filters.destination) {
      const dest = jobDestination(job) ?? 'links-only'
      if (dest !== filters.destination) return false
    }
    return true
  })
}

export function getUniqueProviders(jobs: RealJob[]): string[] {
  const seen = new Set<string>()
  return jobs
    .map(jobProvider)
    .filter((p) => { if (p === '—' || seen.has(p)) return false; seen.add(p); return true })
    .sort()
}

export function getUniqueDestinations(jobs: RealJob[]): string[] {
  const seen = new Set<string>()
  return jobs
    .map((j) => jobDestination(j) ?? 'links-only')
    .filter((d) => { if (seen.has(d)) return false; seen.add(d); return true })
    .sort()
}

export const JOB_STATUS_OPTIONS: { value: JobStatus; label: string }[] = [
  { value: 'created',     label: 'Created'     },
  { value: 'waiting',     label: 'Waiting'     },
  { value: 'running',     label: 'Running'     },
  { value: 'downloading', label: 'Downloading' },
  { value: 'ready',       label: 'Ready'       },
  { value: 'completed',   label: 'Completed'   },
  { value: 'failed',      label: 'Failed'      },
  { value: 'cancelled',   label: 'Cancelled'   },
  { value: 'sending',     label: 'Sending'     },
  { value: 'sent',        label: 'Sent'        },
  { value: 'links_only',  label: 'Links only'  },
]
