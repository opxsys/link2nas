import { useState } from 'react'
import {
  Cloud, Zap, Loader2, Star, PowerOff, Power, Trash2, KeyRound, Pencil,
  FlaskConical, CheckCircle2, XCircle, AlertTriangle,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { testProviderConfig } from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'

const TYPE_ICON: Record<string, LucideIcon> = {
  realdebrid: Zap,
  alldebrid: Cloud,
}

const TYPE_LABEL: Record<string, string> = {
  realdebrid: 'Real-Debrid',
  alldebrid: 'AllDebrid',
}

type TestStatus = 'idle' | 'testing' | 'ok' | 'error'

interface Props {
  config: ProviderConfig
  acting: boolean
  isLastActiveDefault: boolean
  onEdit: () => void
  onToggleEnabled: () => void
  onSetDefault: () => void
  onDelete: () => void
  onReload: () => void
}

export default function ProviderRow({
  config, acting, isLastActiveDefault,
  onEdit, onToggleEnabled, onSetDefault, onDelete, onReload,
}: Props) {
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testMessage, setTestMessage] = useState('')

  const Icon = TYPE_ICON[config.provider_type] ?? Cloud
  const typeLabel = TYPE_LABEL[config.provider_type] ?? config.provider_type
  const expiresAt = config.account_expires_at ? new Date(config.account_expires_at) : null
  const isExpired = expiresAt ? expiresAt < new Date() : false

  async function handleTest() {
    setTestStatus('testing')
    setTestMessage('')
    try {
      const result = await testProviderConfig(config.id)
      const username = result.provider_user?.['username'] as string | undefined
      setTestStatus('ok')
      setTestMessage(username ? `Connected — ${username}` : 'Connected')
      onReload()
    } catch (err) {
      setTestStatus('error')
      setTestMessage(err instanceof ApiError ? err.message : 'Test failed')
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
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">Active</span>
          )}
          {config.is_default && (
            <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">Default</span>
          )}
          {config.has_api_key && (
            <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <KeyRound size={10} aria-hidden="true" /> API key set
            </span>
          )}
          {isExpired && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <AlertTriangle size={10} aria-hidden="true" /> Expired
            </span>
          )}
        </div>

        {expiresAt && (
          <p className={`mt-0.5 text-xs ${isExpired ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'}`}>
            {isExpired ? 'Expired' : 'Expires'}: {expiresAt.toLocaleDateString()}
          </p>
        )}

        {testStatus !== 'idle' && (
          <div className="mt-1 flex items-center gap-1.5 text-xs">
            {testStatus === 'testing' && <Loader2 size={11} className="animate-spin text-muted-foreground" aria-hidden="true" />}
            {testStatus === 'ok'      && <CheckCircle2 size={11} className="text-green-600 dark:text-green-400" aria-hidden="true" />}
            {testStatus === 'error'   && <XCircle size={11} className="text-destructive" aria-hidden="true" />}
            <span className={testStatus === 'error' ? 'text-destructive' : testStatus === 'ok' ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'}>
              {testStatus === 'testing' ? 'Testing…' : testMessage}
            </span>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={acting}
          aria-label={`Edit ${config.name}`} title="Edit" onClick={onEdit}>
          <Pencil size={13} aria-hidden="true" />
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || testStatus === 'testing' || !config.is_enabled}
          aria-label={`Test ${config.name}`}
          title={!config.is_enabled ? 'Enable provider first' : 'Test connection'}
          onClick={handleTest}>
          {testStatus === 'testing'
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : <FlaskConical size={13} aria-hidden="true" />}
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || (config.is_default && !isLastActiveDefault)}
          title={
            config.is_default && !isLastActiveDefault ? 'Set another provider as default first'
              : isLastActiveDefault ? 'Disable — this will leave no active provider'
              : config.is_enabled ? 'Disable' : 'Enable'
          }
          aria-label={config.is_enabled ? `Disable ${config.name}` : `Enable ${config.name}`}
          onClick={onToggleEnabled}>
          {acting
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : config.is_enabled ? <PowerOff size={13} aria-hidden="true" /> : <Power size={13} aria-hidden="true" />}
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={acting || config.is_default || !config.is_enabled}
          title={!config.is_enabled ? 'Enable provider first' : config.is_default ? 'Already default' : 'Set as default'}
          aria-label={`Set ${config.name} as default`} onClick={onSetDefault}>
          <Star size={13} className={config.is_default ? 'fill-primary text-primary' : ''} aria-hidden="true" />
        </Button>

        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
          disabled={acting} aria-label={`Delete ${config.name}`} onClick={onDelete}>
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
