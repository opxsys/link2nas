import {
  CheckCircle2,
  XCircle,
  Download,
  Play,
  AlertTriangle,
  Info,
  MailX,
} from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { NotificationEvent, EventType } from './notifications.types'
import { MOCK_EVENTS } from './notifications.mock'

const EVENT_CONFIG: Record<EventType, { icon: React.ReactNode; className: string }> = {
  job_completed: { icon: <CheckCircle2 size={15} aria-hidden="true" />, className: 'text-green-600 dark:text-green-400' },
  job_failed:    { icon: <XCircle size={15} aria-hidden="true" />,      className: 'text-red-600 dark:text-red-400' },
  job_started:   { icon: <Play size={15} aria-hidden="true" />,          className: 'text-blue-600 dark:text-blue-400' },
  download_ready:{ icon: <Download size={15} aria-hidden="true" />,      className: 'text-emerald-600 dark:text-emerald-400' },
  provider_failed:{ icon: <AlertTriangle size={15} aria-hidden="true" />,className: 'text-orange-600 dark:text-orange-400' },
  system_warning:{ icon: <Info size={15} aria-hidden="true" />,          className: 'text-muted-foreground' },
}

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email',
  gotify: 'Gotify',
  webhook: 'Webhook',
  'in-app': 'In-app',
}

function EventRow({ event }: { event: NotificationEvent }) {
  const cfg = EVENT_CONFIG[event.eventType]
  return (
    <li className={`flex items-start gap-3 py-3 ${!event.read ? 'opacity-100' : 'opacity-70'}`}>
      <span className={`mt-0.5 shrink-0 ${cfg.className}`}>{cfg.icon}</span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-medium text-foreground">{event.title}</span>
          {!event.read && (
            <span className="h-1.5 w-1.5 shrink-0 self-center rounded-full bg-primary" aria-label="Unread" />
          )}
          <span className="text-xs text-muted-foreground">{event.timestamp}</span>
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{event.detail}</p>
        <div className="mt-1 flex items-center gap-2">
          <span className="text-xs text-muted-foreground">via {CHANNEL_LABEL[event.channel]}</span>
          {!event.delivered && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-1.5 py-0.5 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <MailX size={10} aria-hidden="true" />
              Undelivered
            </span>
          )}
        </div>
      </div>
    </li>
  )
}

export default function NotificationEventsTimeline() {
  return (
    <SectionCard title="Recent Events" description="Latest notifications sent to you.">
      <ul className="divide-y divide-border">
        {MOCK_EVENTS.map((event) => (
          <EventRow key={event.id} event={event} />
        ))}
      </ul>
    </SectionCard>
  )
}
