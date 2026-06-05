import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, Loader2, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listDestinationConfigs } from '@/api/destination-configs'
import { ApiError } from '@/api/client'
import type { DestinationConfig } from '@/api/destination-configs'
import DestinationRow from './DestinationRow'
import DestinationModal from './DestinationModal'
import DestinationDeleteModal from './DestinationDeleteModal'

export default function DestinationSettings() {
  const [configs, setConfigs] = useState<DestinationConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const [modalTarget, setModalTarget] = useState<DestinationConfig | null | false>(false)
  const [deleteTarget, setDeleteTarget] = useState<DestinationConfig | null>(null)
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setConfigs(await listDestinationConfigs())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load destinations')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    return () => {
      if (successTimer.current) clearTimeout(successTimer.current)
    }
  }, [])

  function handleSaved() {
    load()
    if (successTimer.current) clearTimeout(successTimer.current)
    setSuccessMessage('Destination saved.')
    successTimer.current = setTimeout(() => setSuccessMessage(null), 4000)
  }

  return (
    <SectionCard
      title="Destinations"
      description="File transfer destinations. Zero active destinations means links-only mode."
      actions={
        <Button variant="outline" size="sm" onClick={() => setModalTarget(null)}>
          <Plus size={13} aria-hidden="true" /> Add destination
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Loading destinations…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && configs.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">
          No destination profiles configured. Add one to enable file transfers, or leave empty for links-only mode.
        </p>
      )}

      {!loading && !error && configs.length > 0 && (
        <div className="flex flex-col gap-3">
          {configs.map((config) => (
            <DestinationRow
              key={config.id}
              config={config}
              onEdit={() => setModalTarget(config)}
              onDelete={() => setDeleteTarget(config)}
              onReload={load}
            />
          ))}
        </div>
      )}

      {successMessage && (
        <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
          <span>{successMessage}</span>
          <button onClick={() => setSuccessMessage(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
            <X size={13} aria-hidden="true" />
          </button>
        </div>
      )}

      {modalTarget !== false && (
        <DestinationModal
          initial={modalTarget}
          onClose={() => setModalTarget(false)}
          onSaved={handleSaved}
        />
      )}

      {deleteTarget && (
        <DestinationDeleteModal
          config={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onDeleted={load}
        />
      )}
    </SectionCard>
  )
}
