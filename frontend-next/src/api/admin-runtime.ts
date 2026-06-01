import { request } from './client'
import type { RuntimeSettings, RuntimeSettingsPayload } from '@/pages/Admin/admin.types'

export function getRuntimeSettings(): Promise<RuntimeSettings> {
  return request<RuntimeSettings>('/api/v2/admin/app-settings/runtime')
}

export function saveRuntimeSettings(payload: RuntimeSettingsPayload): Promise<RuntimeSettings> {
  return request<RuntimeSettings>('/api/v2/admin/app-settings/runtime', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}
