import type { JobStatus } from '@/lib/types'

export interface Job {
  id: string
  name: string
  status: JobStatus
  provider: string
  destination: string | null
  fileCount: number | null
  size: string | null
  created: string
}

export interface JobFile {
  id: string
  name: string
  size: string
  status: JobStatus
}

export interface JobProgress {
  percent: number | null
  downloadedSize: string | null
  speed: string | null
  eta: string | null
  connections: number | null
  provider: string | null
}

export interface JobDetails extends Job {
  jobPath: string | null
  files: JobFile[]
  progress: JobProgress
}

export type JobDetailsTab = 'files' | 'links' | 'details' | 'logs'

export interface JobsFilters {
  search: string
  status: string
  provider: string
  destination: string
}
