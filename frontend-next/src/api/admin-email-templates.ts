import { request } from './client'

export interface EmailTemplate {
  template_key: string
  language: string
  subject_template: string
  body_template: string
  is_custom: boolean
  created_at: string | null
  updated_at: string | null
  updated_by_user_id: string | null
  available_variables: string[]
}

export interface EmailTemplatePreview {
  subject: string
  body: string
  sample_values: Record<string, string>
}

export function getEmailTemplate(key: string, language: string): Promise<EmailTemplate> {
  return request<EmailTemplate>(`/api/v2/admin/email-templates/${key}/${language}`)
}

export function saveEmailTemplate(
  key: string,
  language: string,
  payload: { subject_template: string; body_template: string },
): Promise<EmailTemplate> {
  return request<EmailTemplate>(`/api/v2/admin/email-templates/${key}/${language}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function resetEmailTemplate(key: string, language: string): Promise<EmailTemplate> {
  return request<EmailTemplate>(`/api/v2/admin/email-templates/${key}/${language}/reset`, {
    method: 'POST',
  })
}

export function previewEmailTemplate(
  key: string,
  language: string,
  payload: { subject_template: string; body_template: string },
): Promise<EmailTemplatePreview> {
  return request<EmailTemplatePreview>(`/api/v2/admin/email-templates/${key}/${language}/preview`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
