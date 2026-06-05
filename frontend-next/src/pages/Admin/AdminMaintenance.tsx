import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, CheckCircle2, XCircle, Loader2, AlertCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getMaintenanceStatus } from '@/api/admin-maintenance'
import type { MaintenanceStatus, MaintenancePath } from './admin.types'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`
}

function CheckItem({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-border bg-muted/20 p-3">
      <span className={`mt-0.5 shrink-0 ${ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
        {ok ? <CheckCircle2 size={15} aria-hidden="true" /> : <XCircle size={15} aria-hidden="true" />}
      </span>
      <div className="min-w-0">
        <p className="text-sm font-medium text-foreground">{label}</p>
        <p className="mt-0.5 break-all text-xs text-muted-foreground">{detail}</p>
      </div>
    </div>
  )
}

export default function AdminMaintenance() {
  const [status, setStatus] = useState<MaintenanceStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setStatus(await getMaintenanceStatus())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load maintenance status.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="ml-2 text-sm">Loading…</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">Failed to load maintenance status</p>
          <p className="mt-0.5 text-xs">{error}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
        </div>
      </div>
    )
  }

  if (!status) return null

  const checkedAt = new Date(status.generated_at).toLocaleString()

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${status.ok ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400' : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'}`}>
            {status.ok ? <CheckCircle2 size={12} aria-hidden="true" /> : <XCircle size={12} aria-hidden="true" />}
            {status.ok ? 'All systems OK' : 'Issues detected'}
          </span>
          <span className="text-xs text-muted-foreground">Checked at {checkedAt}</span>
        </div>
        <Button size="sm" variant="outline" onClick={load} disabled={loading}>
          {loading
            ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
            : <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />}
          Refresh
        </Button>
      </div>

      <SectionCard title="Application">
        <div className="grid gap-3 sm:grid-cols-2">
          <CheckItem label="Global status" ok={status.ok} detail={`Checked at ${checkedAt}`} />
          <CheckItem
            label={`${status.app.name} ${status.app.version}`}
            ok={true}
            detail={`Debug: ${status.app.debug ? 'on' : 'off'}${status.app.tagline ? ` — ${status.app.tagline}` : ''}`}
          />
          <CheckItem
            label="Public URL"
            ok={Boolean(status.app.public_base_url)}
            detail={status.app.public_base_url || 'Not configured'}
          />
        </div>
      </SectionCard>

      <SectionCard title="Infrastructure">
        <div className="grid gap-3 sm:grid-cols-2">
          <CheckItem
            label="Database"
            ok={status.database.ok}
            detail={`${status.database.backend} — ${status.database.message}`}
          />
          <CheckItem
            label="Disk space"
            ok={status.disk.ok}
            detail={`${formatBytes(status.disk.free_bytes)} free / ${formatBytes(status.disk.total_bytes)} total — ${status.disk.percent_free}% free`}
          />
        </div>
      </SectionCard>

      <SectionCard title="Directories">
        {status.paths.length === 0 ? (
          <p className="text-sm text-muted-foreground">No directory checks configured.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {status.paths.map((p: MaintenancePath) => (
              <CheckItem
                key={p.name}
                label={`${p.name}${p.required ? '' : ' (optional)'}`}
                ok={p.ok}
                detail={`${p.path ?? '—'} — ${p.message}`}
              />
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  )
}
