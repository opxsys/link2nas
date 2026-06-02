import { CheckCircle2, XCircle, Loader2, Info, AlertTriangle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { NotificationConfig, TestStatus } from './notifications.types'

const SELECT =
  'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

interface Props {
  configs: NotificationConfig[]
  smtpEnabled: boolean | null
  testConfigId: string
  testStatus: TestStatus
  onConfigChange: (id: string) => void
  onSend: () => void
}

export default function NotificationTestPanel({
  configs,
  smtpEnabled,
  testConfigId,
  testStatus,
  onConfigChange,
  onSend,
}: Props) {
  const selectedConfig = configs.find(c => c.id === testConfigId)
  const smtpDisabled = smtpEnabled === false
  const isEmailSelected = selectedConfig?.channel === 'email'
  const blocked = isEmailSelected && smtpDisabled
  const sending = testStatus === 'sending'

  return (
    <SectionCard
      title="Send Test Notification"
      description="Verify a channel is working by sending a test message."
    >
      <div className="flex flex-col gap-4">
        {configs.length === 0 ? (
          <p className="text-sm text-muted-foreground italic">
            No notification channels configured. Add one to test delivery.
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="test-config" className="text-xs font-medium text-foreground">
                  Channel
                </label>
                <select
                  id="test-config"
                  value={testConfigId}
                  onChange={(e) => onConfigChange(e.target.value)}
                  className={SELECT}
                  disabled={sending}
                >
                  {configs.map((cfg) => (
                    <option key={cfg.id} value={cfg.id}>
                      {cfg.name} ({cfg.channel})
                    </option>
                  ))}
                </select>
              </div>
              <Button
                size="sm"
                onClick={onSend}
                disabled={sending || blocked || !testConfigId}
              >
                {sending && (
                  <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                )}
                Send test
              </Button>
            </div>

            {blocked && (
              <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
                SMTP is not configured or disabled. Email sending is unavailable.
              </div>
            )}

            {testStatus === 'sent' && (
              <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2.5 text-sm text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
                <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
                Test notification sent — check your {selectedConfig?.name ?? 'channel'}.
              </div>
            )}
            {testStatus === 'failed' && (
              <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                <XCircle size={15} className="shrink-0" aria-hidden="true" />
                Delivery failed — check channel configuration.
              </div>
            )}
          </>
        )}

        <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
          <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
          Only configured channels are available. Manage channel settings in Settings → Notifications.
        </div>
      </div>
    </SectionCard>
  )
}
