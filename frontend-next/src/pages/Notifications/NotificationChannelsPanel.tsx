import { CheckCircle2, MinusCircle, Mail, Bell, Webhook, Monitor } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { NotificationChannel, ChannelType } from './notifications.types'
import { MOCK_CHANNELS } from './notifications.mock'

const CHANNEL_ICON: Record<ChannelType, React.ReactNode> = {
  email:    <Mail size={18} aria-hidden="true" />,
  gotify:   <Bell size={18} aria-hidden="true" />,
  webhook:  <Webhook size={18} aria-hidden="true" />,
  'in-app': <Monitor size={18} aria-hidden="true" />,
}

function ChannelCard({ channel }: { channel: NotificationChannel }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
        {CHANNEL_ICON[channel.id]}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground">{channel.name}</span>
          {channel.configured ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-green-200 bg-green-50 px-1.5 py-0.5 text-xs text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
              <CheckCircle2 size={10} aria-hidden="true" />
              Configured
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
              <MinusCircle size={10} aria-hidden="true" />
              Not configured
            </span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{channel.description}</p>
        {channel.target && (
          <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{channel.target}</p>
        )}
      </div>
    </div>
  )
}

export default function NotificationChannelsPanel() {
  return (
    <SectionCard
      title="Channels"
      description="Delivery channels available for notification rules."
      actions={
        <a href="#" onClick={(e) => e.preventDefault()} className="text-xs text-primary hover:underline">
          Manage in Settings
        </a>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        {MOCK_CHANNELS.map((ch) => (
          <ChannelCard key={ch.id} channel={ch} />
        ))}
      </div>
    </SectionCard>
  )
}
