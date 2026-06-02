import { useState, useEffect, useCallback } from 'react'
import { Cloud, Zap, Plus, Loader2, Star, PowerOff, Power, Trash2, KeyRound } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import {
  listProviderConfigs,
  updateProviderConfig,
  deleteProviderConfig,
} from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'

const TYPE_ICON: Record<string, LucideIcon> = {
  realdebrid: Zap,
  alldebrid: Cloud,
}

const TYPE_LABEL: Record<string, string> = {
  realdebrid: 'Real-Debrid',
  alldebrid: 'AllDebrid',
}

function ProviderRow({
  config,
  acting,
  isLastActiveDefault,
  onToggleEnabled,
  onSetDefault,
  onDelete,
}: {
  config: ProviderConfig
  acting: boolean
  isLastActiveDefault: boolean
  onToggleEnabled: () => void
  onSetDefault: () => void
  onDelete: () => void
}) {
  const Icon = TYPE_ICON[config.provider_type] ?? Cloud
  const typeLabel = TYPE_LABEL[config.provider_type] ?? config.provider_type
  const expiresAt = config.account_expires_at
    ? new Date(config.account_expires_at).toLocaleDateString()
    : null

  return (
    <div className="flex items-center gap-4 rounded-lg border border-border p-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
        <Icon size={18} aria-hidden="true" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm font-medium text-foreground">{config.name}</span>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
            {typeLabel}
          </span>
          {config.is_enabled && (
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">
              Active
            </span>
          )}
          {config.is_default && (
            <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
              Default
            </span>
          )}
          {config.has_api_key && (
            <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <KeyRound size={10} aria-hidden="true" /> API key set
            </span>
          )}
        </div>
        {expiresAt && (
          <p className="mt-0.5 text-xs text-muted-foreground">Expires: {expiresAt}</p>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        {/* Toggle enable */}
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={acting || (config.is_default && !isLastActiveDefault)}
          title={
            config.is_default && !isLastActiveDefault
              ? 'Set another provider as default first'
              : isLastActiveDefault
              ? 'Disable — this will leave no active provider'
              : config.is_enabled
              ? 'Disable'
              : 'Enable'
          }
          aria-label={config.is_enabled ? `Disable ${config.name}` : `Enable ${config.name}`}
          onClick={onToggleEnabled}
        >
          {acting ? (
            <Loader2 size={13} className="animate-spin" aria-hidden="true" />
          ) : config.is_enabled ? (
            <PowerOff size={13} aria-hidden="true" />
          ) : (
            <Power size={13} aria-hidden="true" />
          )}
        </Button>

        {/* Set default */}
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={acting || config.is_default || !config.is_enabled}
          title={!config.is_enabled ? 'Enable provider first' : config.is_default ? 'Already default' : 'Set as default'}
          aria-label={`Set ${config.name} as default`}
          onClick={onSetDefault}
        >
          <Star size={13} className={config.is_default ? 'fill-primary text-primary' : ''} aria-hidden="true" />
        </Button>

        {/* Delete */}
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-destructive hover:text-destructive"
          disabled={acting}
          aria-label={`Delete ${config.name}`}
          onClick={onDelete}
        >
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}

export default function ProviderSettings() {
  const [configs, setConfigs] = useState<ProviderConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actingIds, setActingIds] = useState<Set<string>>(new Set())

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
    setConfigs(prev => prev.map(c => c.id === config.id ? { ...c, is_enabled: !c.is_enabled } : c))
    try {
      const updated = await updateProviderConfig(config.id, config.provider_type, { is_enabled: !config.is_enabled })
      setConfigs(prev => prev.map(c => c.id === config.id ? updated : c))
    } catch {
      setConfigs(prev => prev.map(c => c.id === config.id ? config : c))
    } finally {
      setActing(config.id, false)
    }
  }

  async function handleSetDefault(config: ProviderConfig) {
    setActing(config.id, true)
    try {
      await updateProviderConfig(config.id, config.provider_type, { is_default: true })
      await load()
    } catch {
      // reload anyway to reflect server state
      await load()
    } finally {
      setActing(config.id, false)
    }
  }

  async function handleDelete(config: ProviderConfig) {
    if (!window.confirm(`Delete provider "${config.name}"? This cannot be undone.`)) return
    setActing(config.id, true)
    try {
      await deleteProviderConfig(config.id)
      setConfigs(prev => prev.filter(c => c.id !== config.id))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete provider')
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
        <Button variant="outline" size="sm" disabled>
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
              onToggleEnabled={() => handleToggleEnabled(config)}
              onSetDefault={() => handleSetDefault(config)}
              onDelete={() => handleDelete(config)}
            />
            )
          })}
          <p className="text-xs text-muted-foreground">
            Adding and editing providers (API key) is not yet available in this UI.
          </p>
        </div>
      )}
    </SectionCard>
  )
}

