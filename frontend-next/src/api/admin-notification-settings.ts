import { request } from './client'
import type { AdminNotificationSettings } from '@/pages/Admin/admin.types'

export function getAdminNotificationSettings(): Promise<AdminNotificationSettings> {
  return request<AdminNotificationSettings>('/api/v2/admin/app-settings/notifications')
}

export function saveAdminNotificationSettings(
  payload: AdminNotificationSettings,
): Promise<AdminNotificationSettings> {
  return request<AdminNotificationSettings>('/api/v2/admin/app-settings/notifications', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}
