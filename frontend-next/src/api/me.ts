import { request } from './client'

export interface MeProfile {
  id: string
  email: string
  display_name: string | null
  role: string
  is_active: boolean
  valid_from: string | null
  account_expires_at: string | null
  email_verified_at: string | null
  email_verified: boolean
  last_login_at: string | null
  force_password_change: boolean
  session_inactivity_minutes: number
  single_user_mode: boolean
  preferred_language: string | null
  email_sending_available: boolean
  receive_application_emails: boolean
  can_use_local_space: boolean
  ui_theme: string
}

export function getMe(): Promise<MeProfile> {
  return request<MeProfile>('/api/v2/me')
}

export function updateMe(payload: {
  display_name?: string | null
  email?: string
  preferred_language?: string | null
  receive_application_emails?: boolean
}): Promise<MeProfile> {
  return request<MeProfile>('/api/v2/me', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function changePassword(payload: {
  current_password: string
  new_password: string
}): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/v2/me/password', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
