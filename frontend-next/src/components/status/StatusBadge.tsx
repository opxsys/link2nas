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
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

interface StatusConfig {
  labelKey: TranslationKey
  icon: LucideIcon
  className: string
}

const NEUTRAL_CLASS =
  'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'

const STATUS_CONFIG: Partial<Record<JobStatus | string, StatusConfig>> = {
  created: {
    labelKey: 'statusFilterCreated',
    icon: Timer,
    className: NEUTRAL_CLASS,
  },
  waiting: {
    labelKey: 'statusFilterWaiting',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  queued: {
    labelKey: 'statusFilterQueued',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  starting: {
    labelKey: 'statusFilterStarting',
    icon: Play,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  running: {
    labelKey: 'statusFilterRunning',
    icon: Play,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  downloading: {
    labelKey: 'statusFilterDownloading',
    icon: CloudDownload,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  downloaded: {
    labelKey: 'statusFilterDownloaded',
    icon: CloudDownload,
    className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  },
  waiting_files_selection: {
    labelKey: 'statusFilterWaitingFiles',
    icon: Clock,
    className: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  },
  partially_ready: {
    labelKey: 'statusFilterPartiallyReady',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  ready: {
    labelKey: 'statusFilterReady',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  completed: {
    labelKey: 'statusFilterCompleted',
    icon: CircleCheck,
    className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  },
  failed: {
    labelKey: 'statusFilterFailed',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  provider_error: {
    labelKey: 'statusFilterProviderError',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  destination_error: {
    labelKey: 'statusFilterDestinationError',
    icon: CircleX,
    className: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  },
  cancelled: {
    labelKey: 'statusFilterCancelled',
    icon: CircleMinus,
    className: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
  },
  cancel_requested: {
    labelKey: 'statusFilterCancelRequested',
    icon: CircleMinus,
    className: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
  },
  sending: {
    labelKey: 'statusFilterSending',
    icon: Send,
    className: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  },
  sent: {
    labelKey: 'statusFilterSent',
    icon: Send,
    className: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300',
  },
  links_only: {
    labelKey: 'statusFilterLinksOnly',
    icon: Link,
    className: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
  },
}

function toReadableLabel(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .toLowerCase()
    .replace(/^\w/, (char) => char.toUpperCase())
}

interface StatusBadgeProps {
  status: JobStatus | string | null | undefined
  className?: string
}

export default function StatusBadge({ status, className }: StatusBadgeProps) {
  const { t } = useI18n()
  const normalizedStatus = String(status ?? '').trim().toLowerCase()
  const knownConfig = normalizedStatus ? STATUS_CONFIG[normalizedStatus] : undefined

  const label = knownConfig
    ? t(knownConfig.labelKey)
    : normalizedStatus
      ? toReadableLabel(normalizedStatus)
      : t('statusUnknown')
  const Icon = knownConfig?.icon ?? CircleHelp
  const badgeClass = knownConfig?.className ?? NEUTRAL_CLASS

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
        badgeClass,
        className,
      )}
      aria-label={`${t('labelStatus')}: ${label}`}
      title={normalizedStatus || 'unknown'}
    >
      <Icon size={12} aria-hidden="true" />
      {label}
    </span>
  )
}
