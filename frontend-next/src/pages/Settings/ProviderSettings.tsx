import { useState, useEffect, useCallback } from 'react'
import { Plus, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listProviderConfigs, updateProviderConfig } from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'
import ProviderRow from './ProviderRow'
import ProviderModal from './ProviderModal'
import ProviderDeleteModal from './ProviderDeleteModal'

export default function ProviderSettings() {
  const [configs, setConfigs] = useState<ProviderConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actingIds, setActingIds] = useState<Set<string>>(new Set())
  const [modalTarget, setModalTarget] = useState<ProviderConfig | null | false>(false)
  const [deleteTarget, setDeleteTarget] = useState<ProviderConfig | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setConfigs(await listProviderConfigs())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load providers')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function setActing(id: string, on: boolean) {
    setActingIds(prev => { const s = new Set(prev); on ? s.add(id) : s.delete(id); return s })
  }

  async function handleToggleEnabled(config: ProviderConfig) {
    setActing(config.id, true)
    setActionError(null)
    setConfigs(prev => prev.map(c => c.id === config.id ? { ...c, is_enabled: !c.is_enabled } : c))
    try {
      const updated = await updateProviderConfig(config.id, config.provider_type, { is_enabled: !config.is_enabled })
      setConfigs(prev => prev.map(c => c.id === config.id ? updated : c))
    } catch (err) {
      setConfigs(prev => prev.map(c => c.id === config.id ? config : c))
      setActionError(err instanceof ApiError ? err.message : 'Could not update provider.')
    } finally {
      setActing(config.id, false)
    }
  }

  async function handleSetDefault(config: ProviderConfig) {
    setActing(config.id, true)
    setActionError(null)
    try {
      await updateProviderConfig(config.id, config.provider_type, { is_default: true })
      await load()
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Could not set default provider.')
      await load()
    } finally {
      setActing(config.id, false)
    }
  }

  const activeProviders = configs.filter(c => c.is_enabled)

  return (
    <SectionCard
      title="Providers"
      description="Download provider profiles. One default per user."
      actions={
        <Button variant="outline" size="sm" onClick={() => setModalTarget(null)}>
          <Plus size={13} aria-hidden="true" /> Add provider
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Loading providers…
        </div>
      )}

      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}

      {!loading && !error && configs.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">
          No provider profiles configured. Add one to start creating jobs.
        </p>
      )}

      {!loading && !error && configs.length > 0 && (
        <div className="flex flex-col gap-3">
          {configs.map((config) => {
            const isLastActiveDefault =
              config.is_default && config.is_enabled && activeProviders.length === 1
            return (
              <ProviderRow
                key={config.id}
                config={config}
                acting={actingIds.has(config.id)}
                isLastActiveDefault={isLastActiveDefault}
                onEdit={() => setModalTarget(config)}
                onToggleEnabled={() => handleToggleEnabled(config)}
                onSetDefault={() => handleSetDefault(config)}
                onDelete={() => setDeleteTarget(config)}
                onReload={load}
              />
            )
          })}
        </div>
      )}

      {actionError && (
        <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          {actionError}
        </div>
      )}

      {modalTarget !== false && (
        <ProviderModal
          initial={modalTarget}
          onClose={() => setModalTarget(false)}
          onSaved={load}
        />
      )}

      {deleteTarget && (
        <ProviderDeleteModal
          config={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onDeleted={load}
        />
      )}
    </SectionCard>
  )
}
