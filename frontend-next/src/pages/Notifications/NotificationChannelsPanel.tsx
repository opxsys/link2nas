import { CheckCircle2, MinusCircle, Mail, Bell, Webhook, AlertTriangle, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { useI18n } from '@/i18n'
import type { NotificationConfig, NotificationChannel } from './notifications.types'

const CHANNEL_ICON: Record<NotificationChannel, React.ReactNode> = {
  email:   <Mail size={18} aria-hidden="true" />,
  gotify:  <Bell size={18} aria-hidden="true" />,
  webhook: <Webhook size={18} aria-hidden="true" />,
}

const CHANNEL_LABEL: Record<NotificationChannel, string> = {
  email:   'Email',
  gotify:  'Gotify',
  webhook: 'Webhook',
}

const CHANNEL_DESC: Record<NotificationChannel, string> = {
  email:   'SMTP email delivery',
  gotify:  'Push via self-hosted Gotify server',
  webhook: 'HTTP POST to a custom URL',
}

function configTarget(cfg: NotificationConfig): string | null {
  const d = cfg.config
  if (cfg.channel === 'email' && d.to_email) return d.to_email
  if (cfg.channel === 'gotify' && d.server_url) return d.server_url
  if (cfg.channel === 'webhook' && d.url) return d.url
  return null
}

function isConfigured(cfg: NotificationConfig): boolean {
  const d = cfg.config
  if (cfg.channel === 'email') return !!d.to_email
  if (cfg.channel === 'gotify') return !!d.server_url
  if (cfg.channel === 'webhook') return !!d.url
  return false
}

function ConfigCard({
  cfg,
  smtpDisabled,
}: {
  cfg: NotificationConfig
  smtpDisabled: boolean
}) {
  const { t } = useI18n()
  const target = configTarget(cfg)
  const configured = isConfigured(cfg)
  const emailWarning = cfg.channel === 'email' && smtpDisabled

  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
        {CHANNEL_ICON[cfg.channel]}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{cfg.name}</span>
          <span className="text-xs text-muted-foreground">({CHANNEL_LABEL[cfg.channel]})</span>
          {configured && cfg.is_enabled ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-green-200 bg-green-50 px-1.5 py-0.5 text-xs text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
              <CheckCircle2 size={10} aria-hidden="true" />
              {t('badgeActive')}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
              <MinusCircle size={10} aria-hidden="true" />
              {!configured ? t('notConfigured') : t('badgeDisabled')}
            </span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{CHANNEL_DESC[cfg.channel]}</p>
        {target && (
          <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{target}</p>
        )}
        {emailWarning && (
          <div className="mt-2 flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-400">
            <AlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden="true" />
            {t('adminSmtpNotTestable')}
          </div>
        )}
      </div>
    </div>
  )
}

interface Props {
  configs: NotificationConfig[]
  smtpEnabled: boolean | null
  loading: boolean
  error: string | null
}

export default function NotificationChannelsPanel({ configs, smtpEnabled, loading, error }: Props) {
  const { t } = useI18n()
  const smtpDisabled = smtpEnabled === false

  return (
    <SectionCard
      title={t('notifChannelsTitle')}
      description={t('notifChannelsDesc')}
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          {t('notifLoadingChannels')}
        </div>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && configs.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">
          {t('notifNoChannels')}
        </p>
      )}
      {!loading && !error && configs.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {configs.map((cfg) => (
            <ConfigCard key={cfg.id} cfg={cfg} smtpDisabled={smtpDisabled} />
          ))}
        </div>
      )}
    </SectionCard>
  )
}
