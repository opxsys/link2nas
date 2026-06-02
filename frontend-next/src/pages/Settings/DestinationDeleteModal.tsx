import { useState } from 'react'
import { Trash2, X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { deleteDestinationConfig } from '@/api/destination-configs'
import { ApiError } from '@/api/client'
import type { DestinationConfig } from '@/api/destination-configs'

interface Props {
  config: DestinationConfig
  onClose: () => void
  onDeleted: () => void
}

export default function DestinationDeleteModal({ config, onClose, onDeleted }: Props) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleDelete() {
    setDeleting(true)
    setError(null)
    try {
      await deleteDestinationConfig(config.id)
      onDeleted()
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete destination.')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog" aria-modal="true" aria-label="Delete destination"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Delete destination</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <div className="p-5">
          <p className="text-sm text-foreground">
            Delete <span className="font-semibold">{config.name}</span>?
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            This is permanent and cannot be undone. Existing jobs that used this destination are not affected.
          </p>
          {error && <p className="mt-3 text-sm text-destructive">{error}</p>}
          <div className="mt-4 flex items-center justify-end gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={deleting}>
              Cancel
            </Button>
            <Button type="button" variant="destructive" size="sm" onClick={handleDelete} disabled={deleting}>
              {deleting && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              <Trash2 size={13} aria-hidden="true" />
              Delete destination
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
