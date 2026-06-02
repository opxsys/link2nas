// Real backend types — mirrors /api/v2/notifications response shapes

export type NotificationChannel = 'email' | 'gotify' | 'webhook'
export type NotificationSeverity = 'info' | 'warning' | 'error' | 'critical'
export type NotificationEventStatus = 'pending' | 'sent' | 'retrying' | 'failed' | 'ignored'
export type TestStatus = 'idle' | 'sending' | 'sent' | 'failed'

export interface NotificationConfigSafeData {
  // email
  to_email?: string
  // gotify
  server_url?: string
  has_token?: boolean
  // webhook
  url?: string
  method?: string
  has_headers?: boolean
}

export interface NotificationConfig {
  id: string
  user_id: string
  name: string
  channel: NotificationChannel
  is_enabled: boolean
  is_default: boolean
  config: NotificationConfigSafeData
  created_at: string
  updated_at: string
}

export interface NotificationRule {
  id: string
  user_id: string
  name: string
  scope: 'user' | 'system'
  is_enabled: boolean
  config_id: string
  severity_min: NotificationSeverity
  event_types: string[]
  rate_limit_per_hour: number
  created_at: string
  updated_at: string
}

export interface NotificationEvent {
  id: string
  user_id: string
  job_id: string | null
  type: string
  scope?: string
  severity: NotificationSeverity
  title: string
  message: string
  payload: Record<string, unknown>
  status: NotificationEventStatus
  attempts: number
  max_attempts: number
  last_error: string | null
  triggered_by_rule_ids: string[]
  triggered_by_config_ids: string[]
  next_retry_at: string | null
  created_at: string
  updated_at: string
  sent_at: string | null
}
