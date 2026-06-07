import { request } from './client'

const TOKEN_KEY = 'link2nas_token'

export interface LoginUser {
  id: string
  email: string
  display_name: string | null
  role: string
  force_password_change: boolean
  session_inactivity_minutes: number
}

export interface LoginResponse {
  token: string
  user: LoginUser
}

export function storeToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function getStoredToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY) } catch { return null }
}

export function login(email: string, password: string): Promise<LoginResponse> {
  return request<LoginResponse>('/api/v2/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export interface SetupStatus {
  setup_required: boolean
  single_user_mode: boolean
}

export function getSetupStatus(): Promise<SetupStatus> {
  return request<SetupStatus>('/api/v2/setup/status')
}

export function createFirstAdmin(params: {
  email: string
  password: string
  display_name?: string | null
  preferred_language?: string | null
}): Promise<{ id: string; email: string; display_name: string | null; role: string }> {
  return request('/api/v2/setup/first-admin', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export function requestPasswordReset(email: string): Promise<{ ok: boolean; message: string }> {
  return request('/api/v2/public/password-reset/request', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })
}

export function requestMagicLogin(email: string): Promise<{ ok: boolean; message: string }> {
  return request('/api/v2/public/magic-login/request', {
    method: 'POST',
    body: JSON.stringify({ email }),
  })
}

export function confirmMagicLogin(token: string): Promise<LoginResponse> {
  return request<LoginResponse>('/api/v2/public/magic-login/confirm', {
    method: 'POST',
    body: JSON.stringify({ token }),
  })
}

export function validatePasswordResetToken(token: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(
    `/api/v2/public/password-reset/validate?token=${encodeURIComponent(token)}`,
  )
}

export function confirmPasswordReset(params: {
  token: string
  password: string
}): Promise<{ ok: boolean; message: string }> {
  return request('/api/v2/public/password-reset/confirm', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export interface TokenStatus {
  valid: boolean
  token_type: string
  expires_at: string
}

export function getTokenStatus(token: string): Promise<TokenStatus> {
  return request<TokenStatus>(`/api/v2/public/tokens/${encodeURIComponent(token)}/status`)
}

export function acceptInvitation(params: {
  token: string
  password: string
}): Promise<{ ok: boolean; message: string }> {
  return request('/api/v2/public/invitations/accept', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export function confirmEmailVerification(token: string): Promise<{ ok: boolean; message: string }> {
  return request('/api/v2/public/email-verification/confirm', {
    method: 'POST',
    body: JSON.stringify({ token }),
  })
}

export function logout(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/v2/auth/logout', { method: 'POST' })
}
