import { useState } from 'react'
import { Trash2, X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cleanupPublicSpace } from '@/api/user-space'
import { ApiError } from '@/api/client'
import { useI18n } from '@/i18n'

interface Props {
  fileCount: number
  onClose: () => void
  onCleaned: () => void
}

export default function UserSpaceCleanupModal({ fileCount, onClose, onCleaned }: Props) {
  const { t } = useI18n()
  const [cleaning, setCleaning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleCleanup() {
    setCleaning(true)
    setError(null)
    try {
      await cleanupPublicSpace()
      onCleaned()
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('cleanupFailed'))
    } finally {
      setCleaning(false)
    }
  }

  const fileWord = fileCount !== 1 ? t('colFiles').toLowerCase() : t('colFile').toLowerCase()

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog" aria-modal="true" aria-label={t('cleanUpTitle')}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{t('cleanUpTitle')}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <div className="p-5">
          <p className="text-sm text-foreground">
            {t('cleanUpConfirmPre')} <span className="font-semibold">{fileCount}</span> {fileWord} {t('cleanUpConfirmPost')}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {t('cleanUpPermanent')}
          </p>
          {error && <p className="mt-3 text-sm text-destructive">{error}</p>}
          <div className="mt-4 flex items-center justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={cleaning}>
              {t('cancel')}
            </Button>
            <Button type="button" variant="destructive" size="sm" onClick={handleCleanup} disabled={cleaning}>
              {cleaning && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              <Trash2 size={13} aria-hidden="true" />
              {t('cleanUpBtn')}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
