export type ChannelType = 'email' | 'gotify' | 'webhook' | 'in-app'
export type EventType =
  | 'job_completed'
  | 'job_failed'
  | 'job_started'
  | 'download_ready'
  | 'provider_failed'
  | 'system_warning'
export type TestStatus = 'idle' | 'sending' | 'sent' | 'failed'

export interface NotificationRule {
  id: string
  event: string
  eventType: EventType
  channel: ChannelType
  target: string
  enabled: boolean
  lastTriggered: string | null
}

export interface NotificationEvent {
  id: string
  eventType: EventType
  title: string
  detail: string
  channel: ChannelType
  delivered: boolean
  read: boolean
  timestamp: string
}

export interface NotificationChannel {
  id: ChannelType
  name: string
  description: string
  configured: boolean
  target: string | null
}
