import { useState } from 'react'
import { Trash2, X, Loader2, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface Props {
  title: string
  description: string
  /** When >0, renders an amber warning that N linked rules will also be deleted. */
  linkedCount?: number
  onClose: () => void
  onConfirm: () => Promise<void>
}

export default function NotifDeleteModal({ title, description, linkedCount = 0, onClose, onConfirm }: Props) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleConfirm() {
    setDeleting(true)
    setError(null)
    try {
      await onConfirm()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed.')
      setDeleting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog" aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <div className="p-5">
          <p className="text-sm text-muted-foreground">{description}</p>
          {linkedCount > 0 && (
            <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              <span>
                This channel is linked to <strong>{linkedCount}</strong> notification rule{linkedCount > 1 ? 's' : ''}.
                {linkedCount > 1 ? ' They' : ' It'} will also be permanently deleted.
              </span>
            </div>
          )}
          {error && (
            <p className="mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}
          <div className="mt-4 flex justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={deleting}>
              Cancel
            </Button>
            <Button type="button" variant="destructive" size="sm" onClick={handleConfirm} disabled={deleting}>
              {deleting
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Trash2 size={13} className="mr-1.5" aria-hidden="true" />}
              Delete
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
