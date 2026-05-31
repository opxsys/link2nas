import type { JobStatus } from '@/lib/types'

export const MOCK_METRICS = {
  activeJobs: 3,
  waitingJobs: 5,
  completedToday: 12,
  failedToday: 1,
} as const

export interface MockDefaultConfig {
  providerName: string | null
  destinationName: string | null
  linksOnly: boolean
}

export const MOCK_DEFAULT_CONFIG: MockDefaultConfig = {
  providerName: 'Real-Debrid (perso)',
  destinationName: 'NAS Maison',
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
    id: 'jobs',
    label: '/data/jobs',
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
    provider: 'Real-Debrid (perso)',
    destination: 'NAS Maison',
    created: '29/05/2026 09:54',
  },
  {
    id: '2',
    name: 'Serie.Example.S03E01-S03.Blu.1080p',
    status: 'downloading',
    provider: 'AllDebrid',
    destination: 'NAS Maison',
    created: '29/05/2026 08:32',
  },
  {
    id: '3',
    name: 'Documentary.Example.4K.HDR.BluRay',
    status: 'completed',
    provider: 'Real-Debrid (perso)',
    destination: 'NAS Maison',
    created: '28/05/2026 22:01',
  },
  {
    id: '4',
    name: 'Film.DV.Example.2160p.DDP5.1.Atmos',
    status: 'failed',
    provider: 'Real-Debrid (perso)',
    destination: null,
    created: '28/05/2026 19:17',
  },
  {
    id: '5',
    name: 'Serie.Example.S01E01.720p.BluRay',
    status: 'sent',
    provider: 'AllDebrid',
    destination: 'NAS Maison',
    created: '28/05/2026 17:30',
  },
]
