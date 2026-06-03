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
  files: RealJobFile[]
  // Destination send state
  send_to_destination: boolean
  sent_to_destination: boolean
  destination_status: string | null
  destination_message: string | null
  destination_progress: number
  destination_path: string | null
  sent_to_destination_at: string | null
  // Error
  error_message: string | null
  // Timestamps
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
  cancelled_at: string | null
  // Available configs for "send to other" actions
  active_real_destination_configs: Array<{ id: string; name: string; destination_type: string; is_default: boolean }>
  can_clone_with_other_provider: boolean
  can_send_to_other_destination: boolean
}

export interface BulkCreateResult {
  jobs: Array<{ job: RealJob; reused: boolean; error: string | null }>
}
export interface SingleCreateResult { job: RealJob; reused: boolean; error: string | null }

export const listJobs = (status?: string): Promise<RealJob[]> =>
  request<RealJob[]>(`/api/v2/jobs${status ? `?status=${encodeURIComponent(status)}` : ''}`)

export const getJob = (id: string): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}`)

export const deleteJob = (id: string): Promise<null> =>
  request<null>(`/api/v2/jobs/${id}`, { method: 'DELETE' })

export const startJob  = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/start`,   { method: 'POST' })
export const cancelJob = (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/cancel`,  { method: 'POST' })
export const restartJob= (id: string): Promise<RealJob> => request<RealJob>(`/api/v2/jobs/${id}/restart`, { method: 'POST' })

export const sendToDestination = (id: string, payload?: { destination_config_id?: string }): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/send-to-destination`, { method: 'POST', body: JSON.stringify(payload ?? {}) })

export const resendToDestination = (id: string, payload?: { destination_config_id?: string }): Promise<RealJob> =>
  request<RealJob>(`/api/v2/jobs/${id}/resend`, { method: 'POST', body: JSON.stringify(payload ?? {}) })

export const createBulkJobs = (payload: {
  source_value: string
  provider_config_id?: string
  destination_config_id?: string
  auto_start?: boolean
}): Promise<BulkCreateResult> =>
  request<BulkCreateResult>('/api/v2/jobs/bulk', { method: 'POST', body: JSON.stringify(payload) })

export function createTorrentJob(
  file: File,
  params: { provider_config_id?: string; destination_config_id?: string; auto_start?: boolean },
): Promise<SingleCreateResult> {
  const form = new FormData()
  form.append('file', file)
  if (params.provider_config_id)   form.append('provider_config_id', params.provider_config_id)
  if (params.destination_config_id) form.append('destination_config_id', params.destination_config_id)
  if (params.auto_start !== undefined) form.append('auto_start', String(params.auto_start))
  return request<SingleCreateResult>('/api/v2/jobs/torrent-file', { method: 'POST', body: form })
}
