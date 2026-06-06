import { Trash2, X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { jobName } from './jobs.types'
import type { RealJob } from '@/api/jobs'

interface Props {
  job: RealJob
  pending: boolean
  onConfirm: () => void
  onClose: () => void
}

export default function JobDeleteModal({ job, pending, onConfirm, onClose }: Props) {
  const { t } = useI18n()
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog" aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{t('deleteJobModalTitle')}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <div className="p-5">
          <p className="text-sm text-foreground">
            {t('deleteJobPrefix')} <span className="font-semibold">{jobName(job)}</span>?
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {t('deleteJobPermanent')}
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={pending}>
              {t('cancel')}
            </Button>
            <Button type="button" variant="destructive" size="sm" onClick={onConfirm} disabled={pending}>
              {pending && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              <Trash2 size={13} className="mr-1.5" aria-hidden="true" />
              {t('deleteJobConfirm')}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
