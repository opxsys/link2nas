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

// ── Search ────────────────────────────────────────────────────────────────────

export interface ProwlarrStatusResult {
  available: boolean
  source: 'user' | 'global' | 'none'
  base_url?: string
  version?: string
  active_indexers?: number
  error?: string
}

export interface ProwlarrIndexer {
  id: number
  name: string
  enabled: boolean
  protocol: string
  categories?: number[]
}

export interface ProwlarrSearchResult {
  result_id: string
  title: string
  indexer: string
  size: number | null
  seeders: number | null
  categories: number[]
  has_download: boolean
  has_magnet: boolean
  has_info_url: boolean
}

export interface ProwlarrSearchResponse {
  source: 'user' | 'global'
  results: ProwlarrSearchResult[]
}

export interface ProwlarrSearchPayload {
  query: string
  categories?: number[]
  indexer_ids?: number[]
  limit?: number
  min_seeders?: number
}

export interface ProwlarrCreateJobPayload {
  result_id: string
  provider_name?: string
  provider_config_id?: string
  destination_name?: string
  destination_config_id?: string
}

export interface ProwlarrCreatedJob {
  id: string
  status: string
  source_type: string
}

export function getProwlarrStatus(): Promise<ProwlarrStatusResult> {
  return request<ProwlarrStatusResult>('/api/v2/prowlarr/status')
}

export function getProwlarrIndexers(): Promise<ProwlarrIndexer[]> {
  return request<ProwlarrIndexer[]>('/api/v2/prowlarr/indexers')
}

export function searchProwlarr(payload: ProwlarrSearchPayload): Promise<ProwlarrSearchResponse> {
  return request<ProwlarrSearchResponse>('/api/v2/prowlarr/search', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function createJobFromProwlarr(payload: ProwlarrCreateJobPayload): Promise<ProwlarrCreatedJob> {
  return request<ProwlarrCreatedJob>('/api/v2/prowlarr/jobs', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
