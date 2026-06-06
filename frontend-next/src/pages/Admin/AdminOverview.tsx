import { useState, useEffect, useCallback } from 'react'
import { Users, UserCheck, HardDrive, Mail, CheckCircle2, XCircle, Loader2, RefreshCw } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { getMaintenanceStatus } from '@/api/admin-maintenance'
import { getSmtpSettings } from '@/api/admin-smtp'
import { getGeneralSettings } from '@/api/admin-settings'
import { getRuntimeSettings } from '@/api/admin-runtime'
import { listUsers } from '@/api/admin-users'
import { listAnnouncements } from '@/api/admin-announcements'
import type {
  MaintenanceStatus, RealSmtpSettings, GeneralSettings,
  RuntimeSettings, RealUser, RealAnnouncement,
} from './admin.types'

function fmtBytes(b: number): string {
  if (b === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1)
  return `${(b / Math.pow(1024, i)).toFixed(1)} ${u[i]}`
}

function ok<T>(r: PromiseSettledResult<T>): T | null {
  return r.status === 'fulfilled' ? r.value : null
}

function ConfigRow({ label, value, bad, mono }: { label: string; value: string; bad?: boolean; mono?: boolean }) {
  return (
    <div className="flex items-baseline gap-4 py-2 first:pt-0 last:pb-0">
      <dt className="w-28 shrink-0 text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={`min-w-0 truncate text-sm ${mono ? 'font-mono text-xs' : ''} ${bad ? 'text-red-600 dark:text-red-400' : 'text-foreground'}`}>
        {value}
      </dd>
    </div>
  )
}

export default function AdminOverview() {
  const { t } = useI18n()
  const [maintenance, setMaintenance] = useState<MaintenanceStatus | null>(null)
  const [smtp, setSmtp] = useState<RealSmtpSettings | null>(null)
  const [general, setGeneral] = useState<GeneralSettings | null>(null)
  const [runtime, setRuntime] = useState<RuntimeSettings | null>(null)
  const [users, setUsers] = useState<RealUser[] | null>(null)
  const [announcements, setAnnouncements] = useState<RealAnnouncement[] | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    const [m, s, g, r, u, a] = await Promise.allSettled([
      getMaintenanceStatus(),
      getSmtpSettings(),
      getGeneralSettings(),
      getRuntimeSettings(),
      listUsers(),
      listAnnouncements(),
    ])
    setMaintenance(ok(m))
    setSmtp(ok(s))
    setGeneral(ok(g))
    setRuntime(ok(r))
    setUsers(ok(u))
    setAnnouncements(ok(a))
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  const smtpReady = smtp ? smtp.enabled && smtp.host.trim() !== '' : null
  const now = new Date()

  const userStats = users ? {
    total:      users.length,
    active:     users.filter((u) => u.is_active).length,
    disabled:   users.filter((u) => !u.is_active).length,
    unverified: users.filter((u) => !u.email_verified).length,
    expired:    users.filter((u) => Boolean(u.account_expires_at && new Date(u.account_expires_at) < now)).length,
    superAdmins: users.filter((u) => u.is_super_admin).length,
  } : null

  const runtimeEnabled = runtime ? [
    runtime.notifications.dispatcher.enabled,
    runtime.jobs.orchestrator.enabled,
    runtime.downloads.local_worker.enabled,
  ].filter(Boolean).length : null

  const activeAnn = announcements ? announcements.filter((a) => a.is_active).length : null

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">{t('adminLoadingOverview')}</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Status bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {maintenance ? (
          <div className="flex items-center gap-2">
            {maintenance.ok
              ? <CheckCircle2 size={15} className="text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
              : <XCircle size={15} className="text-red-600 dark:text-red-400" aria-hidden="true" />}
            <span className={`text-sm font-medium ${maintenance.ok
              ? 'text-emerald-700 dark:text-emerald-400'
              : 'text-red-700 dark:text-red-400'}`}>
              {maintenance.ok ? t('adminAllSystemsOk') : t('adminIssuesDetected')}
            </span>
            <span className="text-xs text-muted-foreground">
              · {t('adminCheckedWord')} {new Date(maintenance.generated_at).toLocaleTimeString()}
            </span>
          </div>
        ) : (
          <span className="text-sm text-muted-foreground">{t('adminStatusUnavailable')}</span>
        )}
        <Button size="sm" variant="outline" onClick={load} disabled={loading}>
          {loading
            ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
            : <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />}
          {t('refresh')}
        </Button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MetricCard
          label={t('adminTotalUsers')}
          value={userStats?.total ?? '—'}
          icon={Users}
          description={userStats ? `${userStats.active} ${t('adminCfgActive')}` : undefined}
        />
        <MetricCard
          label={t('adminActiveUsersLabel')}
          value={userStats?.active ?? '—'}
          icon={UserCheck}
          description={userStats ? `${userStats.disabled} ${t('adminCfgDisabled')}` : undefined}
          iconClassName="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
        />
        <MetricCard
          label={t('adminSmtpLabel')}
          value={smtpReady === null ? '—' : smtpReady ? t('adminSmtpReady') : (smtp && smtp.host.trim() !== '') ? t('badgeDisabled') : t('notConfigured')}
          icon={Mail}
          description={smtpReady && smtp?.host ? smtp.host : undefined}
          iconClassName={smtpReady === false ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' : undefined}
        />
        <MetricCard
          label={t('adminDiskFreeLabel')}
          value={maintenance ? `${maintenance.disk.percent_free.toFixed(1)}%` : '—'}
          icon={HardDrive}
          description={maintenance ? `${fmtBytes(maintenance.disk.free_bytes)} ${t('adminCfgAvailable')}` : undefined}
          iconClassName={maintenance && !maintenance.disk.ok ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' : undefined}
        />
      </div>

      {/* Lower two-column grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SectionCard title={t('adminUserAccounts')}>
          {userStats ? (
            <div className="grid grid-cols-3 gap-3">
              {([
                [t('badgeActive'),          userStats.active,      false],
                [t('badgeDisabled'),        userStats.disabled,    userStats.disabled > 0],
                [t('adminStatUnverified'),  userStats.unverified,  userStats.unverified > 0],
                [t('badgeExpired'),         userStats.expired,     userStats.expired > 0],
                [t('adminStatSuperAdmins'), userStats.superAdmins, false],
                [t('adminStatTotal'),       userStats.total,       false],
              ] as [string, number, boolean][]).map(([label, value, warn]) => (
                <div key={label} className="rounded-md border border-border bg-muted/20 p-2.5 text-center">
                  <p className={`text-lg font-semibold ${warn ? 'text-amber-600 dark:text-amber-400' : 'text-foreground'}`}>
                    {value}
                  </p>
                  <p className="mt-0.5 text-xs text-muted-foreground">{label}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('adminUserDataUnavailable')}</p>
          )}
        </SectionCard>

        <SectionCard title={t('adminConfiguration')}>
          {!general && !maintenance && !smtp && runtimeEnabled === null && announcements === null ? (
            <p className="text-sm text-muted-foreground">{t('adminConfigUnavailable')}</p>
          ) : (
          <dl className="divide-y divide-border">
            {general && (
              <ConfigRow
                label="App"
                value={`${general.app_name}${maintenance ? ` v${maintenance.app.version}` : ''}`}
              />
            )}
            {general?.effective_public_base_url && (
              <ConfigRow label="Public URL" value={general.effective_public_base_url} mono />
            )}
            {maintenance && (
              <ConfigRow
                label={t('adminCfgDatabase')}
                value={`${maintenance.database.backend} — ${maintenance.database.ok ? t('adminCfgConnected') : t('adminCfgDbError')}`}
                bad={!maintenance.database.ok}
              />
            )}
            {smtp && (
              <ConfigRow
                label="SMTP"
                value={smtpReady ? `${smtp.host}:${smtp.port}` : t('notConfigured')}
                bad={!smtpReady}
              />
            )}
            {runtimeEnabled !== null && (
              <ConfigRow
                label={t('adminNavRuntime')}
                value={`${runtimeEnabled}/3 ${t('adminCfgSvcEnabled')}`}
                bad={runtimeEnabled < 3}
              />
            )}
            {announcements !== null && (
              <ConfigRow
                label={t('adminNavAnnouncements')}
                value={`${activeAnn} ${t('adminCfgActive')} · ${announcements.length} ${t('adminCfgAnnTotal')}`}
              />
            )}
          </dl>
          )}
        </SectionCard>
      </div>
    </div>
  )
}
