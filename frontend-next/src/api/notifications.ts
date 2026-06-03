import { request } from './client'
import type {
  NotificationConfig,
  NotificationRule,
  NotificationEvent,
} from '@/pages/Notifications/notifications.types'

// Channel-specific config fields (safe subset — secrets never returned by backend)
export interface NotifConfigData {
  to_email?: string                     // email
  server_url?: string                   // gotify
  token?: string                        // gotify (write-only; blank on edit = keep existing)
  url?: string                          // webhook
  method?: string                       // webhook
  headers?: Record<string, string>      // webhook (omit on edit to preserve existing)
}

// -------------------------------------------------------------------------
// Configs (channels)
// -------------------------------------------------------------------------

export function listNotificationConfigs(): Promise<NotificationConfig[]> {
  return request<NotificationConfig[]>('/api/v2/notifications/configs')
}

export function createNotificationConfig(payload: {
  name: string
  channel: 'email' | 'gotify' | 'webhook'
  is_enabled?: boolean
  is_default?: boolean
  config?: NotifConfigData
}): Promise<NotificationConfig> {
  return request<NotificationConfig>('/api/v2/notifications/configs', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateNotificationConfig(
  id: string,
  payload: {
    name?: string
    is_enabled?: boolean
    is_default?: boolean
    config?: NotifConfigData
  },
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

// -------------------------------------------------------------------------
// Rules
// -------------------------------------------------------------------------

export function listNotificationRules(): Promise<NotificationRule[]> {
  return request<NotificationRule[]>('/api/v2/notifications/rules')
}

export function createNotificationRule(payload: {
  name: string
  config_id: string
  scope?: 'user' | 'system'
  is_enabled?: boolean
  severity_min?: string
  event_types?: string[]
  rate_limit_per_hour?: number
}): Promise<NotificationRule> {
  return request<NotificationRule>('/api/v2/notifications/rules', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateNotificationRule(
  id: string,
  payload: {
    name?: string
    config_id?: string
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

// -------------------------------------------------------------------------
// Events (user-scoped)
// -------------------------------------------------------------------------

export function listUserNotificationEvents(limit = 50): Promise<NotificationEvent[]> {
  return request<NotificationEvent[]>(`/api/v2/notifications/events?limit=${limit}`)
}
