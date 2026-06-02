import {
  CheckCircle2,
  XCircle,
  Clock,
  RotateCcw,
  Info,
  AlertTriangle,
  MailX,
  Loader2,
} from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { NotificationEvent, NotificationConfig, NotificationSeverity } from './notifications.types'

const SEVERITY_CONFIG: Record<
  NotificationSeverity,
  { icon: React.ReactNode; className: string }
> = {
  info:     { icon: <Info size={15} aria-hidden="true" />,          className: 'text-muted-foreground' },
  warning:  { icon: <AlertTriangle size={15} aria-hidden="true" />, className: 'text-orange-600 dark:text-orange-400' },
  error:    { icon: <XCircle size={15} aria-hidden="true" />,       className: 'text-red-600 dark:text-red-400' },
  critical: { icon: <AlertTriangle size={15} aria-hidden="true" />, className: 'text-red-700 dark:text-red-300' },
}

const STATUS_BADGE: Record<string, React.ReactNode> = {
  failed: (
    <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-1.5 py-0.5 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
      <MailX size={10} aria-hidden="true" />
      Failed
    </span>
  ),
  retrying: (
    <span className="inline-flex items-center gap-1 rounded-full border border-yellow-200 bg-yellow-50 px-1.5 py-0.5 text-xs text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-400">
      <RotateCcw size={10} aria-hidden="true" />
      Retrying
    </span>
  ),
  pending: (
    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
      <Clock size={10} aria-hidden="true" />
      Pending
    </span>
  ),
  sent: (
    <span className="inline-flex items-center gap-1 rounded-full border border-green-200 bg-green-50 px-1.5 py-0.5 text-xs text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
      <CheckCircle2 size={10} aria-hidden="true" />
      Sent
    </span>
  ),
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

function EventRow({
  event,
  configs,
}: {
  event: NotificationEvent
  configs: NotificationConfig[]
}) {
  const cfg = SEVERITY_CONFIG[event.severity] ?? SEVERITY_CONFIG.info
  const configName = (() => {
    const cid = event.triggered_by_config_ids[0]
    if (!cid) return null
    return configs.find(c => c.id === cid)?.name ?? null
  })()

  return (
    <li className="flex items-start gap-3 py-3">
      <span className={`mt-0.5 shrink-0 ${cfg.className}`}>{cfg.icon}</span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-medium text-foreground">{event.title}</span>
          <span className="text-xs text-muted-foreground">{formatDate(event.created_at)}</span>
        </div>
        {event.message && (
          <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">{event.message}</p>
        )}
        <div className="mt-1 flex flex-wrap items-center gap-2">
          {configName && (
            <span className="text-xs text-muted-foreground">via {configName}</span>
          )}
          {STATUS_BADGE[event.status]}
        </div>
      </div>
    </li>
  )
}

interface Props {
  events: NotificationEvent[]
  configs: NotificationConfig[]
  loading: boolean
  error: string | null
}

export default function NotificationEventsTimeline({ events, configs, loading, error }: Props) {
  return (
    <SectionCard title="Recent Events" description="Latest user notification events.">
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Loading events…
        </div>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && events.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">No notification events yet.</p>
      )}
      {!loading && !error && events.length > 0 && (
        <ul className="divide-y divide-border">
          {events.map((event) => (
            <EventRow key={event.id} event={event} configs={configs} />
          ))}
        </ul>
      )}
    </SectionCard>
  )
}
