import { request } from './client'

export interface UserAnnouncementStatus {
  opened_at: string | null
  read_at: string | null
  acknowledged_at: string | null
}

export interface UserAnnouncement {
  id: string
  title: string
  body: string
  type: string
  severity: string
  is_active: boolean
  require_acknowledgement: boolean
  show_as_banner: boolean
  track_open: boolean
  starts_at: string | null
  ends_at: string | null
  created_at: string
  updated_at: string
  user_status: UserAnnouncementStatus
}

/** Returns all announcements for the current user (active and inactive). */
export function listUserAnnouncements(): Promise<UserAnnouncement[]> {
  return request<UserAnnouncement[]>('/api/v2/announcements')
}

/** Returns only currently active announcements (respects is_active + date window). */
export function listActiveAnnouncements(): Promise<UserAnnouncement[]> {
  return request<UserAnnouncement[]>('/api/v2/announcements/active')
}

export function markAnnouncementRead(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/announcements/${id}/read`, { method: 'POST' })
}

export function acknowledgeAnnouncement(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/announcements/${id}/acknowledge`, { method: 'POST' })
}

export function markAnnouncementOpened(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/announcements/${id}/open`, { method: 'POST' })
}
