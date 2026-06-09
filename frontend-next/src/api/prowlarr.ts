import { request } from './client'

export interface ProwlarrConfigSafe {
  enabled: boolean
  base_url: string
  has_api_key: boolean
  label?: string | null
  tested_at?: string | null
  last_test_status?: string | null
  last_test_message?: string | null
  created_at?: string
  updated_at?: string
}

export interface ProwlarrAdminPayload {
  enabled: boolean
  base_url: string
  api_key?: string
  label?: string
}

export interface ProwlarrUserPayload {
  enabled: boolean
  base_url: string
  api_key?: string
}

export interface ProwlarrTestResult {
  ok: boolean
  message?: string
  version?: string
  active_indexers?: number
  source?: string
}

export interface ProwlarrMeState {
  user_config: ProwlarrConfigSafe | null
  effective_config_source: 'user' | 'global' | 'none'
  search_available: boolean
}

export function getAdminProwlarr(): Promise<ProwlarrConfigSafe> {
  return request<ProwlarrConfigSafe>('/api/v2/admin/prowlarr')
}

export function saveAdminProwlarr(payload: ProwlarrAdminPayload): Promise<ProwlarrConfigSafe> {
  return request<ProwlarrConfigSafe>('/api/v2/admin/prowlarr', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function testAdminProwlarr(): Promise<ProwlarrTestResult> {
  return request<ProwlarrTestResult>('/api/v2/admin/prowlarr/test', { method: 'POST' })
}

export function getMeProwlarr(): Promise<ProwlarrMeState> {
  return request<ProwlarrMeState>('/api/v2/me/prowlarr')
}

export function saveMeProwlarr(payload: ProwlarrUserPayload): Promise<ProwlarrConfigSafe> {
  return request<ProwlarrConfigSafe>('/api/v2/me/prowlarr', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function testMeProwlarr(): Promise<ProwlarrTestResult> {
  return request<ProwlarrTestResult>('/api/v2/me/prowlarr/test', { method: 'POST' })
}
