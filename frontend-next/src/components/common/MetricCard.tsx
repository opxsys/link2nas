import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface MetricCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  description?: string
  iconClassName?: string
}

export default function MetricCard({
  label,
  value,
  icon: Icon,
  description,
  iconClassName,
}: MetricCardProps) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {label}
          </p>
          <p className="mt-1.5 text-3xl font-bold leading-none text-foreground">
            {value}
          </p>
          {description && (
            <p className="mt-1.5 text-xs text-muted-foreground">{description}</p>
          )}
        </div>
        <div
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary',
            iconClassName,
          )}
        >
          <Icon size={18} aria-hidden="true" />
        </div>
      </div>
    </div>
  )
}
