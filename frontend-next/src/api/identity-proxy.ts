import { request } from './client'
import type { LoginResponse } from './auth'

export function identityProxyLogin(): Promise<LoginResponse> {
  return request<LoginResponse>('/api/v2/auth/identity-proxy/login', { method: 'POST' })
}
