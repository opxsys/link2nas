import { request } from './client'

export interface DestinationSafeConfig {
  // synology
  synology_url?: string
  username?: string
  has_password?: boolean
  verify_ssl?: boolean
  destination_base?: string
  // local
  base_path?: string
}

export interface DestinationConfig {
  id: string
  user_id: string
  name: string
  destination_type: string     // 'synology' | 'local'
  destination_name: string     // v2 compat alias
  is_enabled: boolean
  is_default: boolean
  config: DestinationSafeConfig
  created_at: string
  updated_at: string
}

export interface DestinationTestResult {
  ok: boolean
  message?: string
  error?: string
  destination_type?: string
  destination_profile_name?: string
}

export function listDestinationConfigs(): Promise<DestinationConfig[]> {
  return request<DestinationConfig[]>('/api/v2/destinations')
}

export function saveDestinationConfig(payload: {
  destination_config_id?: string
  destination_type: string
  name: string
  config_json: string          // JSON-encoded config object
  is_enabled: boolean
  is_default: boolean
}): Promise<DestinationConfig> {
  return request<DestinationConfig>('/api/v2/destinations', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function deleteDestinationConfig(id: string): Promise<null> {
  return request<null>(`/api/v2/destinations/${id}`, { method: 'DELETE' })
}

export function testDestinationConfig(id: string): Promise<DestinationTestResult> {
  return request<DestinationTestResult>(`/api/v2/destinations/${id}/test`, { method: 'POST' })
}
