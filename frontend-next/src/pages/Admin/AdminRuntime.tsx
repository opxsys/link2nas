import { useState, useEffect, useCallback } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { getRuntimeSettings, saveRuntimeSettings } from '@/api/admin-runtime'
import type { DispatcherSettings, OrchestratorSettings, LocalWorkerSettings } from './admin.types'
import AdminRuntimeFields from './AdminRuntimeFields'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

type DispatcherFields = Pick<DispatcherSettings, 'enabled' | 'interval_seconds' | 'limit'>
type DispatcherRuntime = Pick<DispatcherSettings, 'last_run_at' | 'last_error'>

const DEFAULT_DISPATCHER: DispatcherFields = { enabled: true, interval_seconds: 60, limit: 25 }
const DEFAULT_ORCHESTRATOR: OrchestratorSettings = {
  enabled: true, interval_seconds: 5, max_jobs_per_run: 25,
  auto_refresh_enabled: true, auto_unrestrict_enabled: true, auto_send_destination_enabled: true,
}
const DEFAULT_LOCAL_WORKER: LocalWorkerSettings = { enabled: true, poll_interval_seconds: 5, max_concurrent_downloads: 1 }

export default function AdminRuntime() {
  const [dispatcher, setDispatcher] = useState<DispatcherFields>(DEFAULT_DISPATCHER)
  const [dispatcherRuntime, setDispatcherRuntime] = useState<DispatcherRuntime>({})
  const [orchestrator, setOrchestrator] = useState<OrchestratorSettings>(DEFAULT_ORCHESTRATOR)
  const [localWorker, setLocalWorker] = useState<LocalWorkerSettings>(DEFAULT_LOCAL_WORKER)

  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getRuntimeSettings()
      const d = data.notifications.dispatcher
      setDispatcher({ enabled: d.enabled, interval_seconds: d.interval_seconds, limit: d.limit })
      setDispatcherRuntime({ last_run_at: d.last_run_at, last_error: d.last_error })
      setOrchestrator(data.jobs.orchestrator)
      setLocalWorker(data.downloads.local_worker)
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load runtime settings.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleDispatcher(key: keyof DispatcherFields, value: boolean | number) {
    setDispatcher((p) => ({ ...p, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  function handleOrchestrator(key: keyof OrchestratorSettings, value: boolean | number) {
    setOrchestrator((p) => ({ ...p, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  function handleLocalWorker(key: keyof LocalWorkerSettings, value: boolean | number) {
    setLocalWorker((p) => ({ ...p, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveRuntimeSettings({
        notifications: { dispatcher },
        jobs: { orchestrator },
        downloads: { local_worker: localWorker },
      })
      const d = updated.notifications.dispatcher
      setDispatcher({ enabled: d.enabled, interval_seconds: d.interval_seconds, limit: d.limit })
      setOrchestrator(updated.jobs.orchestrator)
      setLocalWorker(updated.downloads.local_worker)
      setSaveStatus('saved')
      setSaveMessage('Runtime settings saved.')
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">Loading…</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">Failed to load runtime settings</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'

  return (
    <form onSubmit={handleSave} className="flex flex-col gap-4">
      <AdminRuntimeFields
        dispatcher={dispatcher}
        dispatcherRuntime={dispatcherRuntime}
        orchestrator={orchestrator}
        localWorker={localWorker}
        disabled={busy}
        onDispatcher={handleDispatcher}
        onOrchestrator={handleOrchestrator}
        onLocalWorker={handleLocalWorker}
      />

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" size="sm" disabled={busy}>
          {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
          Save settings
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={load}>
          <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />
          Refresh
        </Button>
        {saveStatus === 'saved' && (
          <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
            <CheckCircle2 size={14} aria-hidden="true" /> {saveMessage}
          </span>
        )}
        {saveStatus === 'error' && (
          <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
            <XCircle size={14} aria-hidden="true" /> {saveMessage}
          </span>
        )}
      </div>
    </form>
  )
}
