import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n'
import type { JobProgress } from './jobs.types'

interface JobProgressCardProps {
  progress: JobProgress
}

function progressBarClass(percent: number): string {
  if (percent >= 100) return 'bg-emerald-500'
  if (percent === 0) return 'bg-muted-foreground/40'
  return 'bg-primary'
}

function StatRow({ label, value }: { label: string; value: string | number | null }) {
  return (
    <div className="flex items-baseline gap-3">
      <span className="w-24 shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className="text-xs font-medium text-foreground">{value ?? '—'}</span>
    </div>
  )
}

export default function JobProgressCard({ progress }: JobProgressCardProps) {
  const { t } = useI18n()
  const percent = progress.percent ?? 0
  const hasStats =
    progress.downloadedSize !== null ||
    progress.speed !== null ||
    progress.eta !== null ||
    (progress.connections !== null && progress.connections > 0)

  return (
    <div className="border-t border-border p-5">
      <p className="mb-2 text-xs font-semibold text-foreground">{t('progress')}</p>

      <div className="mb-1.5 flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{t('overall')}</span>
        <span className="font-medium text-foreground">
          {progress.percent !== null ? `${percent}%` : t('unknown')}
        </span>
      </div>

      <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={cn('h-full rounded-full transition-all', progressBarClass(percent))}
          style={{ width: `${Math.min(percent, 100)}%` }}
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`${t('progress')}: ${percent}%`}
        />
      </div>

      {hasStats && (
        <div className="mt-3 space-y-1.5">
          {progress.downloadedSize && <StatRow label={t('downloaded')} value={progress.downloadedSize} />}
          {progress.speed && <StatRow label={t('speed')} value={progress.speed} />}
          {progress.eta && <StatRow label={t('eta')} value={progress.eta} />}
          {progress.connections !== null && progress.connections > 0 && (
            <StatRow label={t('connections')} value={progress.connections} />
          )}
          {progress.provider && <StatRow label={t('colProvider')} value={progress.provider} />}
        </div>
      )}

      {!hasStats && progress.percent === null && (
        <p className="mt-2 text-xs text-muted-foreground">{t('noProgressData')}</p>
      )}
    </div>
  )
}
