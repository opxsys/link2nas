import { useState, useEffect, useCallback } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, Play } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getCleanupSettings, saveCleanupSettings, runCleanupNow } from '@/api/admin-cleanup'
import type { CleanupRetention, CleanupRunResult } from './admin.types'

const INPUT = 'h-9 w-24 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type RunStatus = 'idle' | 'running' | 'done' | 'failed'

const RETENTION_FIELDS: { key: keyof CleanupRetention; label: string; hint: string }[] = [
  { key: 'completed_jobs_days',  label: 'Completed jobs',    hint: '1–3650' },
  { key: 'failed_jobs_days',     label: 'Failed jobs',       hint: '1–3650' },
  { key: 'cancelled_jobs_days',  label: 'Cancelled jobs',    hint: '1–3650' },
  { key: 'expired_tokens_days',  label: 'Expired tokens',    hint: '1–365'  },
  { key: 'torrent_tmp_days',     label: 'Temp torrent files', hint: '1–365' },
]

const DEFAULT_RETENTION: CleanupRetention = {
  torrent_tmp_days: 7,
  completed_jobs_days: 30,
  failed_jobs_days: 30,
  cancelled_jobs_days: 15,
  expired_tokens_days: 7,
}

export default function AdminCleanup() {
  const [retention, setRetention] = useState<CleanupRetention>(DEFAULT_RETENTION)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const [runStatus, setRunStatus] = useState<RunStatus>('idle')
  const [runResult, setRunResult] = useState<CleanupRunResult | null>(null)
  const [runError, setRunError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await getCleanupSettings()
      setRetention(data.retention)
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load cleanup settings.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleChange(key: keyof CleanupRetention, value: number) {
    setRetention((prev) => ({ ...prev, [key]: value }))
    if (saveStatus !== 'idle') { setSaveStatus('idle'); setSaveMessage('') }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveCleanupSettings({ retention })
      setRetention(updated.retention)
      setSaveStatus('saved')
      setSaveMessage('Cleanup settings saved.')
    } catch (err) {
      setSaveStatus('error')
      setSaveMessage(err instanceof Error ? err.message : 'Save failed.')
    }
  }

  async function handleRun() {
    setRunStatus('running')
    setRunResult(null)
    setRunError('')
    try {
      const result = await runCleanupNow()
      setRunResult(result)
      setRunStatus('done')
    } catch (err) {
      setRunStatus('failed')
      setRunError(err instanceof Error ? err.message : 'Cleanup run failed.')
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
          <p className="font-medium">Failed to load cleanup settings</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'

  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        title="Retention Settings"
        description="Records older than these thresholds are removed during cleanup runs."
      >
        <form onSubmit={handleSave} className="flex flex-col gap-5">
          {RETENTION_FIELDS.map(({ key, label, hint }) => (
            <div key={key} className="flex items-center justify-between gap-4">
              <label htmlFor={`cleanup-${key}`} className="text-sm text-foreground">
                {label}
                <span className="ml-1.5 text-xs text-muted-foreground">({hint} days)</span>
              </label>
              <div className="flex shrink-0 items-center gap-2">
                <input
                  id={`cleanup-${key}`}
                  type="number"
                  className={INPUT}
                  value={retention[key]}
                  disabled={busy}
                  min={1}
                  onChange={(e) => handleChange(key, Number(e.target.value))}
                />
                <span className="text-xs text-muted-foreground">days</span>
              </div>
            </div>
          ))}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <Button type="submit" size="sm" disabled={busy}>
              {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              Save settings
            </Button>
            {saveStatus === 'saved' && (
              <span className="flex items-center gap-1.5 text-sm text-green-700 dark:text-green-400">
                <CheckCircle2 size={14} aria-hidden="true" />
                {saveMessage}
              </span>
            )}
            {saveStatus === 'error' && (
              <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
                <XCircle size={14} aria-hidden="true" />
                {saveMessage}
              </span>
            )}
          </div>
        </form>
      </SectionCard>

      <SectionCard title="Manual Cleanup" description="Trigger an immediate cleanup run outside the schedule.">
        <div className="flex flex-col gap-3">
          <div>
            <Button size="sm" variant="outline" onClick={handleRun} disabled={runStatus === 'running'}>
              {runStatus === 'running'
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Play size={13} className="mr-1.5" aria-hidden="true" />}
              Run cleanup now
            </Button>
          </div>

          {runStatus === 'done' && runResult && (
            <div className="rounded-md border border-green-200 bg-green-50 px-4 py-3 dark:border-green-800 dark:bg-green-950">
              <div className="flex items-center gap-2 text-sm font-medium text-green-700 dark:text-green-400">
                <CheckCircle2 size={15} aria-hidden="true" />
                Cleanup completed
              </div>
              <ul className="mt-2 space-y-0.5 text-xs text-green-700 dark:text-green-400">
                <li>Completed jobs: {runResult.completed_jobs_deleted} removed</li>
                <li>Failed jobs: {runResult.failed_jobs_deleted} removed</li>
                <li>Cancelled jobs: {runResult.cancelled_jobs_deleted} removed</li>
                <li>Expired tokens: {runResult.tokens_deleted} removed</li>
                <li>Temp files: {runResult.temp_files_deleted} removed</li>
              </ul>
              {runResult.temp_files_errors.length > 0 && (
                <ul className="mt-2 space-y-0.5 text-xs text-amber-700 dark:text-amber-400">
                  {runResult.temp_files_errors.map((msg, i) => (
                    <li key={i}>{msg}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {runStatus === 'failed' && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              {runError}
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  )
}
