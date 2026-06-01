import { request } from './client'
import type { CleanupSettings, CleanupRunResult } from '@/pages/Admin/admin.types'

export function getCleanupSettings(): Promise<CleanupSettings> {
  return request<CleanupSettings>('/api/v2/admin/app-settings/cleanup')
}

export function saveCleanupSettings(payload: CleanupSettings): Promise<CleanupSettings> {
  return request<CleanupSettings>('/api/v2/admin/app-settings/cleanup', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function runCleanupNow(): Promise<CleanupRunResult> {
  return request<CleanupRunResult>('/api/v2/admin/cleanup/run', { method: 'POST' })
}
