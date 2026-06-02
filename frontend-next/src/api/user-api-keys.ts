import { request } from './client'

export interface UserApiKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  is_active: boolean
  revoked_at: string | null
  last_used_at: string | null
  created_at: string
  updated_at: string
}

export interface CreatedApiKey extends UserApiKey {
  key: string
}

export function listMyApiKeys(): Promise<UserApiKey[]> {
  return request<UserApiKey[]>('/api/v2/me/api-keys')
}

export function createApiKey(payload: { name: string; scopes: string[] }): Promise<CreatedApiKey> {
  return request<CreatedApiKey>('/api/v2/me/api-keys', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function revokeApiKey(keyId: string): Promise<UserApiKey> {
  return request<UserApiKey>(`/api/v2/me/api-keys/${keyId}/revoke`, { method: 'POST' })
}

export function deleteApiKey(keyId: string): Promise<void> {
  return request<void>(`/api/v2/me/api-keys/${keyId}`, { method: 'DELETE' })
}
