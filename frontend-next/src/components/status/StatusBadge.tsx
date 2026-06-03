import {
  Timer,
  Clock,
  Play,
  CloudDownload,
  CircleCheck,
  CircleX,
  CircleMinus,
  Send,
  Link,
  CircleHelp,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { JobStatus } from '@/lib/types'

interface StatusConfig {
  label: string
  icon: LucideIcon
  className: string
}

const NEUTRAL_CLASS =
  'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'

const STATUS_CONFIG: Partial<Record<JobStatus | string, StatusConfig>> = {
  created: {
    label: 'Created',
    icon: Timer,
    className: NEUTRAL_CLASS,
  },
  waiting: {
    label: 'Waiting',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  queued: {
    label: 'Queued',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  starting: {
    label: 'Starting',
    icon: Play,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  running: {
    label: 'Running',
    icon: Play,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  downloading: {
    label: 'Downloading',
    icon: CloudDownload,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  downloaded: {
    label: 'Downloaded',
    icon: CloudDownload,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  waiting_files_selection: {
    label: 'Waiting files selection',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  partially_ready: {
    label: 'Partially ready',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  ready: {
    label: 'Ready',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  completed: {
    label: 'Completed',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  failed: {
    label: 'Failed',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  provider_error: {
    label: 'Provider error',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  destination_error: {
    label: 'Destination error',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  cancelled: {
    label: 'Cancelled',
    icon: CircleMinus,
    className: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
  },
  cancel_requested: {
    label: 'Cancel requested',
    icon: CircleMinus,
    className: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
  },
  sending: {
    label: 'Sending',
    icon: Send,
    className: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  },
  sent: {
    label: 'Sent',
    icon: Send,
    className: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300',
  },
  links_only: {
    label: 'Links only',
    icon: Link,
    className: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
  },
}

interface StatusBadgeProps {
  status: JobStatus | string | null | undefined
  className?: string
}

function toReadableLabel(value: string): string {
  const normalized = value.trim()

  if (!normalized) {
    return 'Unknown'
  }

  return normalized
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .toLowerCase()
    .replace(/^\w/, (char) => char.toUpperCase())
}

export default function StatusBadge({ status, className }: StatusBadgeProps) {
  const normalizedStatus = String(status ?? '').trim().toLowerCase()
  const knownConfig = normalizedStatus ? STATUS_CONFIG[normalizedStatus] : undefined

  const config: StatusConfig = knownConfig ?? {
    label: toReadableLabel(normalizedStatus),
    icon: CircleHelp,
    className: NEUTRAL_CLASS,
  }

  const Icon = config.icon

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
        config.className,
        className,
      )}
      aria-label={`Status: ${config.label}`}
      title={normalizedStatus || 'unknown'}
    >
      <Icon size={12} aria-hidden="true" />
      {config.label}
    </span>
  )
}
