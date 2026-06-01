import { request } from './client'
import type { AdminNotificationEvent, NotificationEventStatus } from '@/pages/Admin/admin.types'

export function listNotificationEvents(options?: {
  limit?: number
  status?: NotificationEventStatus
}): Promise<AdminNotificationEvent[]> {
  const params = new URLSearchParams()
  if (options?.limit) params.set('limit', String(options.limit))
  if (options?.status) params.set('status', options.status)
  const qs = params.toString()
  return request<AdminNotificationEvent[]>(
    `/api/v2/admin/notifications/events${qs ? `?${qs}` : ''}`,
  )
}
