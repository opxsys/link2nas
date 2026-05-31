export type AdminSection =
  | 'overview'
  | 'users'
  | 'announcements'
  | 'smtp'
  | 'security'
  | 'runtime'
  | 'cleanup'
  | 'system-events'
  | 'maintenance'
  | 'general'
  | 'timeouts'

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

// Real API response types for GET /api/v2/admin/maintenance/status
export interface MaintenanceApp {
  name: string
  tagline: string
  version: string
  debug: boolean
  public_base_url: string
}

export interface MaintenanceDatabase {
  backend: string
  ok: boolean
  message: string
}

export interface MaintenancePath {
  name: string
  path: string | null
  required: boolean
  exists: boolean
  is_dir: boolean
  writable: boolean
  ok: boolean
  message: string
}

export interface MaintenanceDisk {
  ok: boolean
  path: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  percent_used: number
  percent_free: number
  message: string
}

export interface MaintenanceStatus {
  ok: boolean
  generated_at: string
  app: MaintenanceApp
  database: MaintenanceDatabase
  paths: MaintenancePath[]
  disk: MaintenanceDisk
}

// Real API types for GET/PUT /api/v2/admin/app-settings/general
export interface GeneralSettings {
  app_name: string
  app_tagline: string
  public_base_url: string
  effective_public_base_url: string
}

export interface GeneralSettingsPayload {
  app_name: string
  app_tagline: string
  public_base_url: string
}

// Real API types for GET/PUT /api/v2/admin/timeouts/restart-cooldowns
export interface RestartCooldowns {
  default_seconds: number
  realdebrid_seconds: number
  alldebrid_seconds: number
}
