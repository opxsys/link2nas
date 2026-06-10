import { CheckCircle2, XCircle, X } from 'lucide-react'
import { useI18n } from '@/i18n'

export interface StatusBannerProps {
  color: 'green' | 'red'
  message: string
  onDismiss: () => void
}

export default function StatusBanner({ color, message, onDismiss }: StatusBannerProps) {
  const { t } = useI18n()
  const Icon = color === 'green' ? CheckCircle2 : XCircle
  const cls =
    color === 'green'
      ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400'
      : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'
  return (
    <div className={`flex items-center gap-2 rounded-md border px-3 py-2.5 text-sm ${cls}`}>
      <Icon size={15} className="shrink-0" aria-hidden="true" />
      <span className="flex-1">{message}</span>
      <button
        type="button"
        onClick={onDismiss}
        className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        aria-label={t('dismiss')}
      >
        <X size={13} aria-hidden="true" />
      </button>
    </div>
  )
}
