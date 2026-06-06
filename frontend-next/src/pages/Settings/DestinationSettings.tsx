import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, Loader2, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listDestinationConfigs } from '@/api/destination-configs'
import { ApiError } from '@/api/client'
import type { DestinationConfig } from '@/api/destination-configs'
import { useI18n } from '@/i18n'
import DestinationRow from './DestinationRow'
import DestinationModal from './DestinationModal'
import DestinationDeleteModal from './DestinationDeleteModal'

export default function DestinationSettings() {
  const { t } = useI18n()
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
      setError(err instanceof ApiError ? err.message : t('destinationLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    return () => {
      if (successTimer.current) clearTimeout(successTimer.current)
    }
  }, [])

  function handleSaved() {
    load()
    if (successTimer.current) clearTimeout(successTimer.current)
    setSuccessMessage(t('destinationSaved'))
    successTimer.current = setTimeout(() => setSuccessMessage(null), 4000)
  }

  return (
    <SectionCard
      title={t('sectionDestinations')}
      description={t('destinationsDesc')}
      actions={
        <Button variant="outline" size="sm" onClick={() => setModalTarget(null)}>
          <Plus size={13} aria-hidden="true" /> {t('addDestination')}
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          {t('loadingDestinations')}
        </div>
      )}

      {!loading && error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && configs.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">
          {t('noDestinationsConfigured')}
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
          <button onClick={() => setSuccessMessage(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
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
