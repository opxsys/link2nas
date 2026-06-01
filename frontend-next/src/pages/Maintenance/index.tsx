import { useState, useEffect, useCallback } from 'react'
import { Loader2, AlertCircle, RefreshCw } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import MaintenanceHealth from './MaintenanceHealth'
import MaintenanceInfo from './MaintenanceInfo'
import MaintenanceDirs from './MaintenanceDirs'
import { getMaintenanceStatus } from '@/api/admin-maintenance'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'

export default function Maintenance() {
  const [status, setStatus] = useState<MaintenanceStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setStatus(await getMaintenanceStatus())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load system status.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <>
      <PageHeader
        title="System Status"
        description="Quick operational health check — infrastructure, services, and directories at a glance."
      />
      <div className="space-y-6">
        {loading && (
          <div className="flex items-center gap-2 py-12 text-muted-foreground">
            <Loader2 size={18} className="animate-spin" aria-hidden="true" />
            <span className="text-sm">Loading system status…</span>
          </div>
        )}
        {error && (
          <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
            <div>
              <p className="font-medium">Failed to load system status</p>
              <p className="mt-0.5 text-xs">{error}</p>
              <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
            </div>
          </div>
        )}
        {status && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">
                Checked at {new Date(status.generated_at).toLocaleString()}
              </span>
              <Button size="sm" variant="outline" onClick={load}>
                <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />
                Refresh
              </Button>
            </div>
            <MaintenanceHealth status={status} />
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <MaintenanceInfo status={status} />
              <MaintenanceDirs status={status} />
            </div>
          </>
        )}
      </div>
    </>
  )
}
