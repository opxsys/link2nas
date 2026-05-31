import type { HealthStatus } from '@/lib/types'

export interface MockHealthService {
  id: string
  name: string
  status: HealthStatus
  statusLabel: string
  detail?: string
}

export const MOCK_HEALTH_SERVICES: MockHealthService[] = [
  { id: 'app', name: 'Application', status: 'ok', statusLabel: 'Running' },
  { id: 'database', name: 'Database', status: 'ok', statusLabel: 'Connected' },
  { id: 'redis', name: 'Redis', status: 'ok', statusLabel: 'Connected' },
  { id: 'disk', name: 'Disk', status: 'ok', statusLabel: '96% free' },
  { id: 'worker', name: 'Worker', status: 'ok', statusLabel: 'Running' },
]

export interface MockInfoRow {
  key: string
  value: string
  available: boolean
}

export const MOCK_SYSTEM_INFO: MockInfoRow[] = [
  { key: 'Version', value: '3.0.0', available: true },
  { key: 'Environment', value: 'Production', available: true },
  { key: 'Python', value: 'Not available', available: false },
  { key: 'Database', value: 'SQLite', available: true },
  { key: 'Redis', value: 'Connected', available: true },
  { key: 'Uptime', value: 'Not available', available: false },
]

export type DirStatus = 'ok' | 'error' | 'unknown'

export interface MockDirectory {
  label: string
  path: string
  status: DirStatus
}

export const MOCK_DIRECTORIES: MockDirectory[] = [
  { label: 'Data', path: '/data', status: 'ok' },
  { label: 'Temp', path: '/tmp', status: 'ok' },
  { label: 'User data', path: '/data/userdata', status: 'ok' },
  { label: 'Logs', path: '/logs', status: 'ok' },
  { label: 'Torrent storage', path: '/tmp/torrents', status: 'unknown' },
  { label: 'Downloads', path: '/downloads', status: 'ok' },
]
