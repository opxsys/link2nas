import { useState } from 'react'
import {
  Cloud, Loader2, Star, PowerOff, Power, Trash2, KeyRound, Pencil,
  FlaskConical, CheckCircle2, XCircle, AlertTriangle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { testProviderConfig } from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'
import { useI18n } from '@/i18n'
import { PROVIDER_ICON as TYPE_ICON, PROVIDER_LABEL as TYPE_LABEL } from '@/lib/provider-types'

type TestStatus = 'idle' | 'testing' | 'ok' | 'error'

function formatProviderExpiry(value: string | null): string | null {
  if (!value) return null
  const d = new Date(value)
  if (isNaN(d.getTime())) return value
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' })
}

interface Props {
  config: ProviderConfig
  actingAction: 'toggle' | 'default' | null
  isLastActiveDefault: boolean
  onEdit: () => void
  onToggleEnabled: () => void
  onSetDefault: () => void
  onDelete: () => void
  onReload: () => void
}

export default function ProviderRow({
  config, actingAction, isLastActiveDefault,
  onEdit, onToggleEnabled, onSetDefault, onDelete,
}: Props) {
  const { t } = useI18n()
  const acting = actingAction !== null
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testMessage, setTestMessage] = useState('')

  const Icon = TYPE_ICON[config.provider_type] ?? Cloud
  const typeLabel = TYPE_LABEL[config.provider_type] ?? config.provider_type
  const expiryLabel = formatProviderExpiry(config.account_expires_at)
  const expiresAt = config.account_expires_at ? new Date(config.account_expires_at) : null
  const isExpired = expiresAt && !isNaN(expiresAt.getTime()) ? expiresAt < new Date() : false

  async function handleTest() {
    setTestStatus('testing')
    setTestMessage('')
    try {
      const result = await testProviderConfig(config.id)
      const username = result.provider_user?.['username'] as string | undefined
      setTestStatus('ok')
      setTestMessage(username ? `${t('providerConnected')} — ${username}` : t('providerConnected'))
    } catch (err) {
      setTestStatus('error')
      setTestMessage(err instanceof ApiError ? err.message : t('testFailed'))
    }
  }

  return (
    <div className="flex items-start gap-4 rounded-lg border border-border p-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
        <Icon size={18} aria-hidden="true" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm font-medium text-foreground">{config.name}</span>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">{typeLabel}</span>
          {config.is_enabled && (
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">{t('badgeActive')}</span>
          )}
          {config.is_default && (
            <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">{t('badgeDefault')}</span>
          )}
          {config.has_api_key && (
            <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <KeyRound size={10} aria-hidden="true" /> {t('badgeApiKeySet')}
            </span>
          )}
          {isExpired && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <AlertTriangle size={10} aria-hidden="true" /> {t('badgeExpired')}
            </span>
          )}
        </div>

        {expiryLabel && (
          <p className={`mt-0.5 text-xs ${isExpired ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'}`}>
            {isExpired ? t('badgeExpired') : t('labelExpires')}: {expiryLabel}
          </p>
        )}

        {testStatus === 'testing' && (
          <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Loader2 size={11} className="animate-spin" aria-hidden="true" />
            <span>{t('testing')}</span>
          </div>
        )}

        {testStatus === 'ok' && (
          <div className="mt-2 flex items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1.5 text-xs text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <CheckCircle2 size={11} aria-hidden="true" />
            <span>{testMessage}</span>
          </div>
        )}

        {testStatus === 'error' && (
          <div className="mt-2 flex items-center gap-1.5 rounded-md border border-red-200 bg-red-50 px-2.5 py-1.5 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={11} aria-hidden="true" />
            <span>{testMessage}</span>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={acting}
          aria-label={`${t('titleEdit')} ${config.name}`} title={t('titleEdit')} onClick={onEdit}>
          <Pencil size={13} aria-hidden="true" />
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || testStatus === 'testing' || !config.is_enabled}
          aria-label={`${t('testConnection')} ${config.name}`}
          title={!config.is_enabled ? t('provEnableFirst') : t('testConnection')}
          onClick={handleTest}>
          {testStatus === 'testing'
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : <FlaskConical size={13} aria-hidden="true" />}
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || (config.is_default && !isLastActiveDefault)}
          title={
            config.is_default && !isLastActiveDefault ? t('provSetAnotherDefault')
              : isLastActiveDefault ? t('provDisableLastWarning')
              : config.is_enabled ? t('titleDisable') : t('titleEnable')
          }
          aria-label={config.is_enabled ? `${t('titleDisable')} ${config.name}` : `${t('titleEnable')} ${config.name}`}
          onClick={onToggleEnabled}>
          {acting && actingAction === 'toggle'
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : config.is_enabled ? <PowerOff size={13} aria-hidden="true" /> : <Power size={13} aria-hidden="true" />}
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || config.is_default || !config.is_enabled}
          title={!config.is_enabled ? t('provEnableFirst') : config.is_default ? t('alreadyDefault') : t('setAsDefault')}
          aria-label={`${t('setAsDefault')} ${config.name}`} onClick={onSetDefault}>
          {acting && actingAction === 'default'
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : <Star size={13} className={config.is_default ? 'fill-primary text-primary' : ''} aria-hidden="true" />}
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
          disabled={acting} aria-label={`${t('delete')} ${config.name}`} onClick={onDelete}>
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
