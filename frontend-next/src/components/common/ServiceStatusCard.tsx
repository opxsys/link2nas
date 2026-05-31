import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { HealthStatus } from '@/lib/types'

interface ServiceStatusCardProps {
  name: string
  icon: LucideIcon
  status: HealthStatus
  statusLabel: string
  detail?: string
}

const DOT_CLASS: Record<HealthStatus, string> = {
  ok: 'bg-emerald-500',
  warning: 'bg-amber-500',
  error: 'bg-red-500',
  unknown: 'bg-muted-foreground',
}

const LABEL_CLASS: Record<HealthStatus, string> = {
  ok: 'text-emerald-700 dark:text-emerald-400',
  warning: 'text-amber-700 dark:text-amber-400',
  error: 'text-red-700 dark:text-red-400',
  unknown: 'text-muted-foreground',
}

export default function ServiceStatusCard({
  name,
  icon: Icon,
  status,
  statusLabel,
  detail,
}: ServiceStatusCardProps) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-3">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
        <Icon size={18} aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-foreground">{name}</p>
        {detail && (
          <p className="truncate text-xs text-muted-foreground">{detail}</p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        <span
          className={cn('h-2 w-2 rounded-full', DOT_CLASS[status])}
          aria-hidden="true"
        />
        <span className={cn('text-xs font-medium', LABEL_CLASS[status])}>
          {statusLabel}
        </span>
      </div>
    </div>
  )
}
