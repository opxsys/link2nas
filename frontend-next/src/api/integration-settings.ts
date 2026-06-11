import { request } from './client'

export type ProwlarrOpenMode = 'iframe' | 'new_tab' | 'both'

export interface IntegrationSettings {
  prowlarr_enabled: boolean
  prowlarr_url: string
  prowlarr_open_mode: ProwlarrOpenMode
  home_page: string
  /** True when native Prowlarr search is configured (user or global admin). */
  native_search_available: boolean
}

export function getIntegrationSettings(): Promise<IntegrationSettings> {
  return request<IntegrationSettings>('/api/v2/me/integration-settings')
}

export function updateIntegrationSettings(payload: Partial<IntegrationSettings>): Promise<IntegrationSettings> {
  return request<IntegrationSettings>('/api/v2/me/integration-settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}
