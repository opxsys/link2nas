import { request } from './client'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'

export function getMaintenanceStatus(): Promise<MaintenanceStatus> {
  return request<MaintenanceStatus>('/api/v2/admin/maintenance/status')
}
