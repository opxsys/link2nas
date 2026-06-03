import { request } from './client'
import type { JobStatus } from '@/lib/types'

export interface RealJobFile {
  id: string | number
  path: string | null
  filename: string | null
  bytes: number | null
  filesize: number | null
  debrid_link: string | null
  download_url: string | null
}

export interface RealJobDestinationConfig {
  id: string
  name: string
  destination_type: string
  destination_name?: string
  is_default: boolean
}

export interface RealJobProviderConfig {
  id: string
  name: string
  provider_type: string
  provider_name?: string
  is_default: boolean
}

export interface RealJob {
  id: string
  source_type: string
  source_value: string
  status: JobStatus
  allowed_actions: string[]

  // Provider
  provider_config_id: string | null
  provider_name: string | null
  provider_type: string | null
  provider_profile_name: string | null
  provider_resource_id: string | null
  provider_status: string | null
  provider_available: boolean

  // Destination
  destination_config_id: string | null
  destination_name: string | null
  destination_type: string | null
  destination_profile_name: string | null
  destination_available: boolean

  // Output
  output_mode: string | null
  output_links: Array<{ url?: string; debrid_link?: string; filename?: string; filesize?: number }>
  filename: string | null
  filesize: number | null
  progress: number
  download_url: string | null
  debrid_link: string | null
  files: RealJobFile[]

  // Destination send state
  send_to_destination: boolean
  sent_to_destination: boolean
  destination_status: string | null
  destination_message: string | null
  destination_message_key: string | null
  destination_message_params: Record<string, unknown> | null
  destination_progress: number
  destination_path: string | null
  destination_display_path: string | null
  destination_last_attempt: string | null
  sent_to_destination_at: string | null

  // Error
  error_message: string | null

  // Timestamps
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
  cancelled_at: string | null

  // Legacy compat
  torrent_id: string | null
  torrent_status: string | null

  // Available configs for action modals
  active_provider_configs: RealJobProviderConfig[]
  active_real_destination_configs: RealJobDestinationConfig[]
  can_clone_with_other_provider: boolean
  can_send_to_other_destination: boolean
}

export interface BulkCreateResult {
  jobs: Array<{ job: RealJob; reused: boolean; error: string | null }>
}

export interface SingleCreateResult {
  job: RealJob
  reused: boolean
  error: string | null
}

export interface CloneResult {
  job: RealJob
  reused: boolean
}

// ── List / Get ─────────────────────────────────────────────────────────────

export const listJobs = (status?: string): Promise<RealJob[]> =>
  request<RealJob[]>(`/api/v2/jobs${status ? `?status=${encodeURIComponent(status)}` : ''}`)

export const getJob = (id: string): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}`)

// ── Lifecycle ──────────────────────────────────────────────────────────────

export const startJob   = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/start`,   { method: 'POST' })
export const cancelJob  = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/cancel`,  { method: 'POST' })
export const restartJob = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/restart`, { method: 'POST' })
export const refreshJob = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/refresh`, { method: 'POST' })

export const selectJobFiles = (id: string, files: 'all' | (string | number)[] = 'all'): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/select-files`, { method: 'POST', body: JSON.stringify({ files }) })

export const unrestrictJob = (id: string): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/unrestrict`, { method: 'POST' })

export const unrestrictJobFile = (id: string, fileId: string | number): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/files/${fileId}/unrestrict`, { method: 'POST' })

export const deleteJob = (id: string): Promise<null> =>
  request<null>(`/api/v2/jobs/${id}`, { method: 'DELETE' })

// ── Destination ────────────────────────────────────────────────────────────

export const sendToDestination = (id: string, payload?: { destination_config_id?: string }): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/send-to-destination`, { method: 'POST', body: JSON.stringify(payload ?? {}) })

export const resendToDestination = (id: string, payload?: { destination_config_id?: string }): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/resend`, { method: 'POST', body: JSON.stringify(payload ?? {}) })

export const cancelLocalDownload = (id: string): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/destination/cancel`, { method: 'POST' })

// ── Clone ──────────────────────────────────────────────────────────────────

export const cloneWithProvider = (
  id: string,
  payload: { provider_config_id?: string; provider_name?: string; destination_config_id?: string; auto_start?: boolean },
): Promise<CloneResult> =>
  request<CloneResult>(`/api/v2/jobs/${id}/clone-with-provider`, { method: 'POST', body: JSON.stringify(payload) })

// ── Create ─────────────────────────────────────────────────────────────────

export const createBulkJobs = (payload: {
  source_value: string
  provider_config_id?: string
  destination_config_id?: string
  auto_start?: boolean
  send_to_destination?: boolean
}): Promise<BulkCreateResult> =>
  request<BulkCreateResult>('/api/v2/jobs/bulk', { method: 'POST', body: JSON.stringify(payload) })

export function createTorrentJob(
  file: File,
  params: { provider_config_id?: string; destination_config_id?: string; auto_start?: boolean; send_to_destination?: boolean },
): Promise<SingleCreateResult> {
  const form = new FormData()
  form.append('file', file)
  if (params.provider_config_id)    form.append('provider_config_id',   params.provider_config_id)
  if (params.destination_config_id) form.append('destination_config_id', params.destination_config_id)
  form.append('auto_start',          String(params.auto_start ?? true))
  form.append('send_to_destination', String(params.send_to_destination ?? false))
  return request<SingleCreateResult>('/api/v2/jobs/torrent-file', { method: 'POST', body: form })
}
