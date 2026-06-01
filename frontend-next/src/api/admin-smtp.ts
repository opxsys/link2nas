import { request } from './client'
import type { RealSmtpSettings, SmtpSettingsPayload, SmtpTestResult } from '@/pages/Admin/admin.types'

export function getSmtpSettings(): Promise<RealSmtpSettings> {
  return request<RealSmtpSettings>('/api/v2/admin/smtp-settings')
}

export function saveSmtpSettings(payload: SmtpSettingsPayload): Promise<RealSmtpSettings> {
  return request<RealSmtpSettings>('/api/v2/admin/smtp-settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function testSmtpSettings(): Promise<SmtpTestResult> {
  return request<SmtpTestResult>('/api/v2/admin/smtp-settings/test', { method: 'POST' })
}
