import { request } from './client'

export interface ProviderConfig {
  id: string
  user_id: string
  name: string
  provider_type: string
  provider_name: string  // v2 compat alias for provider_type
  is_enabled: boolean
  is_default: boolean
  has_api_key: boolean
  account_expires_at: string | null
  created_at: string
  updated_at: string
}

export function listProviderConfigs(): Promise<ProviderConfig[]> {
  return request<ProviderConfig[]>('/api/v2/providers')
}

export function updateProviderConfig(
  id: string,
  providerType: string,
  payload: { is_enabled?: boolean; is_default?: boolean },
): Promise<ProviderConfig> {
  return request<ProviderConfig>('/api/v2/providers', {
    method: 'POST',
    body: JSON.stringify({ provider_config_id: id, provider_type: providerType, ...payload }),
  })
}

export function deleteProviderConfig(id: string): Promise<null> {
  return request<null>(`/api/v2/providers/${id}`, { method: 'DELETE' })
}
