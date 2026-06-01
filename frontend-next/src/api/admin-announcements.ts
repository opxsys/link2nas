import { request } from './client'
import type { RealAnnouncement, AnnouncementPayload, AnnouncementTracking } from '@/pages/Admin/admin.types'

export function listAnnouncements(): Promise<RealAnnouncement[]> {
  return request<RealAnnouncement[]>('/api/v2/admin/announcements')
}

export function createAnnouncement(payload: AnnouncementPayload): Promise<RealAnnouncement> {
  return request<RealAnnouncement>('/api/v2/admin/announcements', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateAnnouncement(id: string, payload: Partial<AnnouncementPayload>): Promise<RealAnnouncement> {
  return request<RealAnnouncement>(`/api/v2/admin/announcements/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function deleteAnnouncement(id: string): Promise<null> {
  return request<null>(`/api/v2/admin/announcements/${id}`, { method: 'DELETE' })
}

export function getAnnouncementTracking(id: string): Promise<AnnouncementTracking> {
  return request<AnnouncementTracking>(`/api/v2/admin/announcements/${id}/tracking`)
}
