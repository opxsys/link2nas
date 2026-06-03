import { useState } from 'react'
import { Mail, Zap, Webhook, Pencil, Trash2, FlaskConical, Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { testNotificationConfig } from '@/api/notifications'
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
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<'ok' | 'fail' | null>(null)

  const emailBlocked = config.channel === 'email' && smtpEnabled === false
  const Icon = CHANNEL_ICON[config.channel as keyof typeof CHANNEL_ICON] ?? Mail

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      await testNotificationConfig(config.id)
      setTestResult('ok')
    } catch {
      setTestResult('fail')
    } finally {
      setTesting(false)
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
          {config.is_default && (
            <span className="inline-flex items-center rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[10px] text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">
              Default
            </span>
          )}
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
        {testResult && (
          <p className={`mt-0.5 flex items-center gap-1 text-xs ${testResult === 'ok' ? 'text-green-600 dark:text-green-400' : 'text-destructive'}`}>
            {testResult === 'ok'
              ? <CheckCircle2 size={11} aria-hidden="true" />
              : <XCircle size={11} aria-hidden="true" />}
            {testResult === 'ok' ? 'Test sent successfully.' : 'Test failed.'}
          </p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button
          variant="ghost" size="sm" className="h-7 px-2 text-xs gap-1"
          disabled={testing || emailBlocked || !config.is_enabled}
          onClick={handleTest}
          aria-label={`Test ${config.name}`}
        >
          {testing
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
