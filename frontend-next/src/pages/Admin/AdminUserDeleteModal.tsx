import { useState } from 'react'
import { Trash2, X, Loader2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { deleteUser } from '@/api/admin-users'
import type { RealUser } from './admin.types'
import { useI18n } from '@/i18n'

interface Props {
  user: RealUser
  onDeleted: (userId: string) => void
  onClose: () => void
}

export default function AdminUserDeleteModal({ user, onDeleted, onClose }: Props) {
  const { t } = useI18n()
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleDelete() {
    setDeleting(true)
    setError(null)
    try {
      await deleteUser(user.id)
      onDeleted(user.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('deleteFailed'))
      setDeleting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget && !deleting) onClose() }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{t('adminDeleteUserTitle')}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} disabled={deleting} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>

        <div className="flex flex-col gap-4 p-5">
          <div>
            <p className="text-sm text-foreground">
              {t('delete')} <span className="font-semibold">{user.display_name || user.email}</span>?
            </p>
            {user.display_name && (
              <p className="mt-0.5 text-xs text-muted-foreground">{user.email}</p>
            )}
            <p className="mt-1.5 text-xs text-muted-foreground">
              {t('adminDeleteUserPermanent')}
            </p>
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{error}</span>
              <button
                type="button"
                onClick={() => setError(null)}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={deleting}>
              {t('cancel')}
            </Button>
            <Button type="button" variant="destructive" size="sm" onClick={handleDelete} disabled={deleting}>
              {deleting
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Trash2 size={13} className="mr-1.5" aria-hidden="true" />}
              {t('adminDeleteUserTitle')}
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
