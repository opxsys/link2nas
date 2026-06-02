import { request } from './client'

export interface UserAnnouncement {
  id: string
  title: string
  body: string
  type: string
  severity: string
  is_active: boolean
  require_acknowledgement: boolean
  show_as_banner: boolean
  starts_at: string | null
  ends_at: string | null
  created_at: string
  updated_at: string
  // user read status — null means not yet read/opened/acknowledged
  opened_at: string | null
  read_at: string | null
  acknowledged_at: string | null
}

export function listUserAnnouncements(): Promise<UserAnnouncement[]> {
  return request<UserAnnouncement[]>('/api/v2/announcements')
}

export function markAnnouncementRead(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/announcements/${id}/read`, { method: 'POST' })
}

export function acknowledgeAnnouncement(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/announcements/${id}/acknowledge`, { method: 'POST' })
}
