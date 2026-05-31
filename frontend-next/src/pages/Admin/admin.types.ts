export type AdminSection =
  | 'overview'
  | 'users'
  | 'announcements'
  | 'smtp'
  | 'security'
  | 'runtime'
  | 'cleanup'
  | 'system-events'

export type UserRole = 'admin' | 'user' | 'viewer'
export type UserStatus = 'active' | 'disabled' | 'pending'
export type AnnouncementStatus = 'draft' | 'published'
export type RuntimeStatus = 'running' | 'stopped' | 'error'
export type SystemEventSeverity = 'error' | 'warning' | 'info'
export type TestStatus = 'idle' | 'sending' | 'sent' | 'failed'
export type CleanupStatus = 'idle' | 'running' | 'done' | 'failed'

export interface AdminSummary {
  totalUsers: number
  activeUsers: number
  pendingInvitations: number
  systemEventsToday: number
}

export interface AdminUser {
  id: string
  username: string
  email: string
  role: UserRole
  status: UserStatus
  emailVerified: boolean
  createdAt: string
  lastLogin: string | null
}

export interface Announcement {
  id: string
  title: string
  status: AnnouncementStatus
  requiresAck: boolean
  sendEmail: boolean
  createdAt: string
  publishedAt: string | null
}

export interface SmtpConfig {
  configured: boolean
  provider: string
  host: string
  port: number
  from: string
  tlsEnabled: boolean
}

export interface SecurityConfig {
  tokenTtlDays: number
  sessionInactivityMinutes: number
  passwordMinLength: number
  requireUppercase: boolean
  requireNumbers: boolean
  rateLimitEnabled: boolean
  rateLimitPerMinute: number
}

export interface RuntimeComponent {
  id: string
  name: string
  status: RuntimeStatus
  interval: string | null
  description: string
}

export interface RetentionRule {
  id: string
  target: string
  retainDays: number
  lastRun: string | null
  nextRun: string | null
}

export interface SystemEventTypeDef {
  code: string
  severity: SystemEventSeverity
  deduplicated: boolean
  rateLimited: boolean
  enabled: boolean
  description: string
}

export interface SystemEvent {
  id: string
  code: string
  severity: SystemEventSeverity
  message: string
  timestamp: string
  resolved: boolean
}
