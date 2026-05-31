import { CheckCircle2, XCircle, Loader2, Info } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { ChannelType, TestStatus } from './notifications.types'
import { MOCK_CHANNELS } from './notifications.mock'

const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

interface Props {
  testChannel: ChannelType
  testStatus: TestStatus
  onChannelChange: (ch: ChannelType) => void
  onSend: () => void
}

export default function NotificationTestPanel({ testChannel, testStatus, onChannelChange, onSend }: Props) {
  const configuredChannels = MOCK_CHANNELS.filter((c) => c.configured)

  return (
    <SectionCard
      title="Send Test Notification"
      description="Verify a channel is working by sending a test message."
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="test-channel" className="text-xs font-medium text-foreground">
              Channel
            </label>
            <select
              id="test-channel"
              value={testChannel}
              onChange={(e) => onChannelChange(e.target.value as ChannelType)}
              className={SELECT}
              disabled={testStatus === 'sending'}
            >
              {configuredChannels.map((ch) => (
                <option key={ch.id} value={ch.id}>{ch.name}</option>
              ))}
            </select>
          </div>
          <Button
            size="sm"
            onClick={onSend}
            disabled={testStatus === 'sending'}
          >
            {testStatus === 'sending' && (
              <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
            )}
            Send test
          </Button>
        </div>

        {testStatus === 'sent' && (
          <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2.5 text-sm text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
            <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
            Test notification sent (mock) — check your {testChannel} channel.
          </div>
        )}
        {testStatus === 'failed' && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={15} className="shrink-0" aria-hidden="true" />
            Delivery failed (mock) — check channel configuration.
          </div>
        )}

        <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
          <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
          Only configured channels are available. Manage channel settings in Settings → Notifications.
        </div>
      </div>
    </SectionCard>
  )
}
