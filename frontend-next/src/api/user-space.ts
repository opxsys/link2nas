import { request } from './client'

export interface SpaceFile {
  name: string
  relative_path: string
  size_bytes: number
}

export interface PublicSpace {
  slug: string
  url: string
  file_count: number
  total_size_bytes: number
  files: SpaceFile[]
}

export interface SpaceCleanupResult {
  ok: boolean
  deleted_files: string[]
  deleted_count: number
  deleted_bytes: number
}

export function getPublicSpace(): Promise<PublicSpace> {
  return request<PublicSpace>('/api/v2/me/public-space')
}

export function cleanupPublicSpace(): Promise<SpaceCleanupResult> {
  return request<SpaceCleanupResult>('/api/v2/me/public-space/cleanup', { method: 'POST' })
}
