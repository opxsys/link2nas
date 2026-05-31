import type { JobStatus, HealthStatus } from '@/lib/types'

export const MOCK_METRICS = {
  activeJobs: 3,
  completedToday: 12,
  failedToday: 1,
  totalJobs: 142,
} as const

export interface MockServiceStatus {
  id: string
  name: string
  status: HealthStatus
  statusLabel: string
  detail?: string
}

export const MOCK_SYSTEM_SERVICES: MockServiceStatus[] = [
  { id: 'redis', name: 'Redis', status: 'ok', statusLabel: 'Connected' },
  { id: 'worker', name: 'Worker', status: 'ok', statusLabel: 'Running' },
  { id: 'scheduler', name: 'Scheduler', status: 'ok', statusLabel: 'Running' },
  { id: 'database', name: 'Database', status: 'ok', statusLabel: 'OK', detail: '1% used' },
]

export interface MockDefaultConfig {
  providerName: string | null
  destinationName: string | null
  linksOnly: boolean
}

export const MOCK_DEFAULT_CONFIG: MockDefaultConfig = {
  providerName: 'Bad Debt (pure)',
  destinationName: 'NAS Mount (nfs)',
  linksOnly: false,
}

export interface MockStorageItem {
  id: string
  label: string
  usedLabel: string
  freeLabel: string
  freePercent: number
}

export const MOCK_STORAGE: MockStorageItem[] = [
  {
    id: 'allotted',
    label: 'Allotted',
    usedLabel: '476 MB used',
    freeLabel: '476 MB free',
    freePercent: 99,
  },
  {
    id: 'downloads',
    label: '/downloads',
    usedLabel: '4.2 GB used',
    freeLabel: '18.1 GB free',
    freePercent: 81,
  },
]

export interface MockRecentJob {
  id: string
  name: string
  status: JobStatus
  provider: string
  destination: string | null
  created: string
}

export const MOCK_RECENT_JOBS: MockRecentJob[] = [
  {
    id: '1',
    name: 'Film.Example.2024.1080p.BluRay',
    status: 'completed',
    provider: 'Bad Dest (pure)',
    destination: 'NAS Mount (nfs)',
    created: '29/05/2026 09:54',
  },
  {
    id: '2',
    name: 'Serie.Example.S03E01-S03.Blu.1080p',
    status: 'downloading',
    provider: 'Alldebrid',
    destination: 'NAS Mount (nfs)',
    created: '29/05/2026 08:32',
  },
  {
    id: '3',
    name: 'Documentary.Example.4K.HDR.BluRay',
    status: 'completed',
    provider: 'Bad Dest (pure)',
    destination: 'NAS Mount (nfs)',
    created: '28/05/2026 22:01',
  },
  {
    id: '4',
    name: 'Film.DV.Example.2160p.DDP5.1.Atmos',
    status: 'failed',
    provider: 'NAS Mount',
    destination: null,
    created: '28/05/2026 19:17',
  },
  {
    id: '5',
    name: 'Serie.Example.S01E01.720p.BluRay',
    status: 'sent',
    provider: 'Bad Dest (pure)',
    destination: 'NAS Mount (nfs)',
    created: '28/05/2026 17:30',
  },
]
