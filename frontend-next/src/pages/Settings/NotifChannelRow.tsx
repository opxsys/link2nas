import { useState } from 'react'
import { Mail, Zap, Webhook, Pencil, Trash2, FlaskConical, Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { testNotificationConfig } from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationConfig } from '@/pages/Notifications/notifications.types'

const CHANNEL_ICON = { email: Mail, gotify: Zap, webhook: Webhook } as const
const CHANNEL_LABEL = { email: 'Email', gotify: 'Gotify', webhook: 'Webhook' } as const

interface Props {
  config: NotificationConfig
  smtpEnabled: boolean | null
  onEdit: () => void
  onDelete: () => void
}

export default function NotifChannelRow({ config, smtpEnabled, onEdit, onDelete }: Props) {
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'ok' | 'error'>('idle')
  const [testMessage, setTestMessage] = useState('')

  const emailBlocked = config.channel === 'email' && smtpEnabled === false
  const Icon = CHANNEL_ICON[config.channel as keyof typeof CHANNEL_ICON] ?? Mail

  async function handleTest() {
    setTestStatus('testing')
    setTestMessage('')
    try {
      await testNotificationConfig(config.id)
      setTestStatus('ok')
      setTestMessage('Notification test successful.')
    } catch (err) {
      setTestStatus('error')
      setTestMessage(err instanceof ApiError ? err.message : 'Test failed.')
    }
  }

  return (
    <div className="flex items-center gap-3 rounded-lg border border-border p-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted">
        <Icon size={14} aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm font-medium text-foreground">{config.name}</span>
          <span className="inline-flex items-center rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] text-muted-foreground capitalize">
            {CHANNEL_LABEL[config.channel as keyof typeof CHANNEL_LABEL] ?? config.channel}
          </span>
          {!config.is_enabled && (
            <span className="inline-flex items-center rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
              Disabled
            </span>
          )}
          {emailBlocked && (
            <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[10px] text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              SMTP unavailable
            </span>
          )}
        </div>
        {testStatus === 'testing' && (
          <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Loader2 size={11} className="animate-spin" aria-hidden="true" />
            <span>Testing…</span>
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
        <Button
          variant="ghost" size="sm" className="h-7 px-2 text-xs gap-1"
          disabled={testStatus === 'testing' || emailBlocked || !config.is_enabled}
          onClick={handleTest}
          aria-label={`Test ${config.name}`}
        >
          {testStatus === 'testing'
            ? <Loader2 size={11} className="animate-spin" aria-hidden="true" />
            : <FlaskConical size={11} aria-hidden="true" />}
          <span className="hidden sm:inline">Test</span>
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit ${config.name}`} onClick={onEdit}>
          <Pencil size={13} aria-hidden="true" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" aria-label={`Delete ${config.name}`} onClick={onDelete}>
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
