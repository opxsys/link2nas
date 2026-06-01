import { request } from './client'
import type {
  RealUser,
  UserInvitationResult,
  UserResetLinkResult,
  UserEmailActionResult,
  CreateUserPayload,
  CreateUserResponse,
} from '@/pages/Admin/admin.types'

export function listUsers(): Promise<RealUser[]> {
  return request<RealUser[]>('/api/v2/admin/users')
}

export function createUser(payload: CreateUserPayload): Promise<CreateUserResponse> {
  return request<CreateUserResponse>('/api/v2/admin/users', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function enableUser(id: string): Promise<RealUser> {
  return request<RealUser>(`/api/v2/admin/users/${id}/enable`, { method: 'POST' })
}

export function disableUser(id: string): Promise<RealUser> {
  return request<RealUser>(`/api/v2/admin/users/${id}/disable`, { method: 'POST' })
}

export function deleteUser(id: string): Promise<null> {
  return request<null>(`/api/v2/admin/users/${id}`, { method: 'DELETE' })
}

export function verifyUserEmail(id: string): Promise<RealUser> {
  return request<RealUser>(`/api/v2/admin/users/${id}/verify-email`, { method: 'POST' })
}

export function createInvitationLink(id: string): Promise<UserInvitationResult> {
  return request<UserInvitationResult>(`/api/v2/admin/users/${id}/invitation`, { method: 'POST' })
}

export function sendInvitationEmail(id: string): Promise<UserEmailActionResult> {
  return request<UserEmailActionResult>(`/api/v2/admin/users/${id}/invitation/email`, { method: 'POST' })
}

export function createResetLink(id: string): Promise<UserResetLinkResult> {
  return request<UserResetLinkResult>(`/api/v2/admin/users/${id}/password-reset-link`, { method: 'POST' })
}

export function sendResetEmail(id: string): Promise<UserEmailActionResult> {
  return request<UserEmailActionResult>(`/api/v2/admin/users/${id}/password-reset-link/email`, { method: 'POST' })
}
