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

// Real API types for GET/PUT /api/v2/admin/app-settings/security
export interface SecurityTokenTtl {
  invitation_ttl_hours: number
  password_reset_ttl_hours: number
  magic_login_ttl_minutes: number
  email_verification_ttl_hours: number
  session_inactivity_minutes: number
}

export interface SecurityPasswordPolicy {
  min_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_number: boolean
  require_special: boolean
}

export interface SecuritySettings {
  token_ttl: SecurityTokenTtl
  password_policy: SecurityPasswordPolicy
}

// Real API types for GET /api/v2/admin/security/anti-abuse
export interface AntiAbuseCounter {
  kind: string
  label: string
  limit: number
  window_seconds: number
  configurable: boolean
  status: 'ok' | 'unavailable'
  active_identities?: number | null
  estimated_hits?: number | null
  ttl_seconds?: number | null
}

export interface AntiAbuseStatus {
  backend: string
  redis_enabled: boolean
  redis_url_configured: boolean
  key_prefix: string
  counters: AntiAbuseCounter[]
  note?: string
}

export interface AntiAbuseResetResult {
  ok: boolean
  results?: Record<string, unknown>
  kind?: string
  error?: string
}

// Real API types for GET/PUT /api/v2/admin/app-settings/runtime
export interface DispatcherSettings {
  enabled: boolean
  interval_seconds: number
  limit: number
  last_run_at?: string | null
  last_error?: string | null
  last_result?: unknown
}

export interface OrchestratorSettings {
  enabled: boolean
  interval_seconds: number
  max_jobs_per_run: number
  auto_refresh_enabled: boolean
  auto_unrestrict_enabled: boolean
  auto_send_destination_enabled: boolean
}

export interface LocalWorkerSettings {
  enabled: boolean
  poll_interval_seconds: number
  max_concurrent_downloads: number
}

export interface RuntimeSettings {
  notifications: { dispatcher: DispatcherSettings }
  jobs: { orchestrator: OrchestratorSettings }
  downloads: { local_worker: LocalWorkerSettings }
}

export interface RuntimeSettingsPayload {
  notifications: { dispatcher: Pick<DispatcherSettings, 'enabled' | 'interval_seconds' | 'limit'> }
  jobs: { orchestrator: OrchestratorSettings }
  downloads: { local_worker: LocalWorkerSettings }
}

// Real API types for GET/PUT /api/v2/admin/app-settings/cleanup and POST /api/v2/admin/cleanup/run
export interface CleanupRetention {
  torrent_tmp_days: number
  completed_jobs_days: number
  failed_jobs_days: number
  cancelled_jobs_days: number
  expired_tokens_days: number
}

export interface CleanupSettings {
  retention: CleanupRetention
}

export interface CleanupRunResult {
  enabled: boolean
  started_at: string
  finished_at: string | null
  tokens_deleted: number
  completed_jobs_deleted: number
  failed_jobs_deleted: number
  cancelled_jobs_deleted: number
  temp_files_deleted: number
  temp_files_errors: string[]
}

// Real API types for GET/PUT /api/v2/admin/smtp-settings
export interface RealSmtpSettings {
  enabled: boolean
  host: string
  port: number
  username: string
  has_password: boolean
  from_email: string
  from_name: string
  use_tls: boolean
  use_ssl: boolean
  created_at?: string
  updated_at?: string
}

export interface SmtpSettingsPayload {
  enabled: boolean
  host: string
  port: number
  username: string
  password: string
  from_email: string
  from_name: string
  use_tls: boolean
  use_ssl: boolean
}

export interface SmtpTestResult {
  ok: boolean
  message?: string
  error?: string
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
