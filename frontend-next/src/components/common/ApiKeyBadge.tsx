import { KeyRound } from 'lucide-react'
import { useI18n } from '@/i18n'

interface Props { hasKey: boolean }

export default function ApiKeyBadge({ hasKey }: Props) {
  const { t } = useI18n()
  const cls = hasKey
    ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400'
    : 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-400'
  const label = hasKey ? t('adminProwlarrHasApiKey') : t('adminProwlarrNoApiKey')
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
      <KeyRound size={10} aria-hidden="true" />
      {label}
    </span>
  )
}
