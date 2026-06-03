import { request } from './client'

export interface ControlCenterQueue {
  queue_name: string
  pending_count: number
  started_count: number
  failed_count: number
  scheduled_count: number
  deferred_count: number
  workers_total: number
  workers_busy: number
  workers_idle: number
  workers_names: string[]
}

export interface ControlCenter {
  generated_at: string | null
  provider: string | null
  destination_type: string | null
  jobs_total: number
  jobs_active: number
  jobs_with_destination_pending: number
  status_counts: Record<string, number>
  queue: ControlCenterQueue
  restart_cooldowns: Record<string, number>
}

export function getControlCenter(): Promise<ControlCenter> {
  return request<ControlCenter>('/api/v2/system/control-center')
}
