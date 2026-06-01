import { request } from './client'
import type {
  SecuritySettings,
  AntiAbuseStatus,
  AntiAbuseResetResult,
} from '@/pages/Admin/admin.types'

export function getSecuritySettings(): Promise<SecuritySettings> {
  return request<SecuritySettings>('/api/v2/admin/app-settings/security')
}

export function saveSecuritySettings(payload: SecuritySettings): Promise<SecuritySettings> {
  return request<SecuritySettings>('/api/v2/admin/app-settings/security', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function getAntiAbuse(): Promise<AntiAbuseStatus> {
  return request<AntiAbuseStatus>('/api/v2/admin/security/anti-abuse')
}

export function resetAntiAbuseAll(): Promise<AntiAbuseResetResult> {
  return request<AntiAbuseResetResult>('/api/v2/admin/security/anti-abuse/reset', { method: 'POST' })
}

export function resetAntiAbuseKind(kind: string): Promise<AntiAbuseResetResult> {
  return request<AntiAbuseResetResult>(`/api/v2/admin/security/anti-abuse/reset/${kind}`, { method: 'POST' })
}
