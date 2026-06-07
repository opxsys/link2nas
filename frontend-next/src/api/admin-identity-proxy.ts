import { request } from './client'
import type {
  AdminIdentityProxyConfig,
  AdminIdentityProxyTestResult,
} from '@/pages/Admin/admin.types'

export function getAdminIdentityProxyConfig(): Promise<AdminIdentityProxyConfig> {
  return request<AdminIdentityProxyConfig>('/api/v2/admin/identity-proxy/config')
}

export function patchAdminIdentityProxyConfig(
  payload: Partial<AdminIdentityProxyConfig> & { config?: Record<string, string> },
): Promise<AdminIdentityProxyConfig> {
  return request<AdminIdentityProxyConfig>('/api/v2/admin/identity-proxy/config', {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function testAdminIdentityProxyConfig(): Promise<AdminIdentityProxyTestResult> {
  return request<AdminIdentityProxyTestResult>('/api/v2/admin/identity-proxy/test', {
    method: 'POST',
  })
}
