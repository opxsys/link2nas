import { request } from './client'
import type { AdminOidcProvider, OidcProviderPayload } from '@/pages/Admin/admin.types'

export function listAdminOidcProviders(): Promise<AdminOidcProvider[]> {
  return request<AdminOidcProvider[]>('/api/v2/admin/oidc-providers/')
}

export function createAdminOidcProvider(payload: OidcProviderPayload): Promise<AdminOidcProvider> {
  return request<AdminOidcProvider>('/api/v2/admin/oidc-providers/', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function getAdminOidcProvider(id: string): Promise<AdminOidcProvider> {
  return request<AdminOidcProvider>(`/api/v2/admin/oidc-providers/${id}`)
}

export function updateAdminOidcProvider(
  id: string,
  payload: Partial<OidcProviderPayload>,
): Promise<AdminOidcProvider> {
  return request<AdminOidcProvider>(`/api/v2/admin/oidc-providers/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function deleteAdminOidcProvider(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/v2/admin/oidc-providers/${id}`, {
    method: 'DELETE',
  })
}

export function testAdminOidcProviderDiscovery(
  id: string,
): Promise<{ ok: boolean; error?: string }> {
  return request<{ ok: boolean; error?: string }>(
    `/api/v2/admin/oidc-providers/${id}/test-discovery`,
    { method: 'POST' },
  )
}
