import { request } from './client'
import type {
  NotificationConfig,
  NotificationRule,
  NotificationEvent,
} from '@/pages/Notifications/notifications.types'

// Configs (channels)

export function listNotificationConfigs(): Promise<NotificationConfig[]> {
  return request<NotificationConfig[]>('/api/v2/notifications/configs')
}

export function updateNotificationConfig(
  id: string,
  payload: { name?: string; is_enabled?: boolean; is_default?: boolean },
): Promise<NotificationConfig> {
  return request<NotificationConfig>(`/api/v2/notifications/configs/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteNotificationConfig(id: string): Promise<{ deleted: boolean }> {
  return request<{ deleted: boolean }>(`/api/v2/notifications/configs/${id}`, {
    method: 'DELETE',
  })
}

export function testNotificationConfig(id: string): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>(`/api/v2/notifications/configs/${id}/test`, {
    method: 'POST',
  })
}

// Rules

export function listNotificationRules(): Promise<NotificationRule[]> {
  return request<NotificationRule[]>('/api/v2/notifications/rules')
}

export function updateNotificationRule(
  id: string,
  payload: {
    name?: string
    is_enabled?: boolean
    severity_min?: string
    event_types?: string[]
    rate_limit_per_hour?: number
  },
): Promise<NotificationRule> {
  return request<NotificationRule>(`/api/v2/notifications/rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteNotificationRule(id: string): Promise<{ deleted: boolean }> {
  return request<{ deleted: boolean }>(`/api/v2/notifications/rules/${id}`, {
    method: 'DELETE',
  })
}

// Events (user-scoped)

export function listUserNotificationEvents(limit = 50): Promise<NotificationEvent[]> {
  return request<NotificationEvent[]>(`/api/v2/notifications/events?limit=${limit}`)
}
