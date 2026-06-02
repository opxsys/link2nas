import { useState, useEffect, useCallback } from 'react'
import { Plus, Loader2 } from 'lucide-react'
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
  const [modalTarget, setModalTarget] = useState<DestinationConfig | null | false>(false)
  const [deleteTarget, setDeleteTarget] = useState<DestinationConfig | null>(null)

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
        <p className="py-4 text-sm text-destructive">{error}</p>
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

      {modalTarget !== false && (
        <DestinationModal
          initial={modalTarget}
          onClose={() => setModalTarget(false)}
          onSaved={load}
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
