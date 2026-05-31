import { request } from './client'
import type {
  GeneralSettings,
  GeneralSettingsPayload,
  RestartCooldowns,
} from '@/pages/Admin/admin.types'

export function getGeneralSettings(): Promise<GeneralSettings> {
  return request<GeneralSettings>('/api/v2/admin/app-settings/general')
}

export function saveGeneralSettings(payload: GeneralSettingsPayload): Promise<GeneralSettings> {
  return request<GeneralSettings>('/api/v2/admin/app-settings/general', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function getRestartCooldowns(): Promise<RestartCooldowns> {
  return request<RestartCooldowns>('/api/v2/admin/timeouts/restart-cooldowns')
}

export function saveRestartCooldowns(payload: RestartCooldowns): Promise<RestartCooldowns> {
  return request<RestartCooldowns>('/api/v2/admin/timeouts/restart-cooldowns', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}
