import { useState, useEffect, useCallback, useRef } from 'react'
import { CheckCircle2, XCircle, Loader2, AlertCircle, Play, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getCleanupSettings, saveCleanupSettings, runCleanupNow } from '@/api/admin-cleanup'
import type { CleanupRetention, CleanupRunResult } from './admin.types'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

const INPUT = 'h-9 w-24 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type RunStatus = 'idle' | 'running' | 'done' | 'failed'

const DEFAULT_RETENTION: CleanupRetention = {
  torrent_tmp_days: 7,
  completed_jobs_days: 30,
  failed_jobs_days: 30,
  cancelled_jobs_days: 15,
  expired_tokens_days: 7,
}

export default function AdminCleanup() {
  const { t } = useI18n()

  const RETENTION_FIELDS: { key: keyof CleanupRetention; labelKey: TranslationKey; hint: string; max: number }[] = [
    { key: 'completed_jobs_days',  labelKey: 'adminCleanupCompletedJobs',  hint: '1–3650', max: 3650 },
    { key: 'failed_jobs_days',     labelKey: 'adminCleanupFailedJobs',     hint: '1–3650', max: 3650 },
    { key: 'cancelled_jobs_days',  labelKey: 'adminCleanupCancelledJobs',  hint: '1–3650', max: 3650 },
    { key: 'expired_tokens_days',  labelKey: 'adminCleanupExpiredTokens',  hint: '1–365',  max: 365  },
    { key: 'torrent_tmp_days',     labelKey: 'adminCleanupTempTorrents',   hint: '1–365',  max: 365  },
  ]

  const [retention, setRetention] = useState<CleanupRetention>(DEFAULT_RETENTION)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [saveMessage, setSaveMessage] = useState('')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

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
    if (saveTimer.current) clearTimeout(saveTimer.current)
    setSaveStatus('saving')
    setSaveMessage('')
    try {
      const updated = await saveCleanupSettings({ retention })
      setRetention(updated.retention)
      setSaveStatus('saved')
      setSaveMessage(t('adminCleanupSaved'))
      saveTimer.current = setTimeout(() => setSaveStatus('idle'), 4000)
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

  function dismissRun() {
    setRunStatus('idle')
    setRunResult(null)
    setRunError('')
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-muted-foreground">
        <Loader2 size={20} className="animate-spin" aria-hidden="true" />
        <span className="text-sm">{t('loading')}</span>
      </div>
    )
  }

  if (fetchError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        <div>
          <p className="font-medium">{t('adminLoadCleanupFailed')}</p>
          <p className="mt-0.5 text-xs">{fetchError}</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
        </div>
      </div>
    )
  }

  const busy = saveStatus === 'saving'

  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        title={t('adminRetentionTitle')}
        description={t('adminRetentionDesc')}
      >
        <form onSubmit={handleSave} className="flex flex-col gap-5">
          {RETENTION_FIELDS.map(({ key, labelKey, hint, max }) => (
            <div key={key} className="flex items-center justify-between gap-4">
              <label htmlFor={`cleanup-${key}`} className="text-sm text-foreground">
                {t(labelKey)}
                <span className="ml-1.5 text-xs text-muted-foreground">({hint} {t('unitDays')})</span>
              </label>
              <div className="flex shrink-0 items-center gap-2">
                <input
                  id={`cleanup-${key}`}
                  type="number"
                  className={INPUT}
                  value={retention[key]}
                  disabled={busy}
                  min={1}
                  max={max}
                  onChange={(e) => handleChange(key, Number(e.target.value))}
                />
                <span className="text-xs text-muted-foreground">{t('unitDays')}</span>
              </div>
            </div>
          ))}

          <div className="flex flex-col gap-3 pt-1">
            <div>
              <Button type="submit" size="sm" disabled={busy}>
                {busy && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
                {t('adminSaveSettings')}
              </Button>
            </div>
            {saveStatus === 'saved' && (
              <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
                <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
                <span className="flex-1">{saveMessage}</span>
                <button
                  type="button"
                  onClick={() => { if (saveTimer.current) clearTimeout(saveTimer.current); setSaveStatus('idle') }}
                  className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={t('dismiss')}
                >
                  <X size={13} aria-hidden="true" />
                </button>
              </div>
            )}
            {saveStatus === 'error' && (
              <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                <XCircle size={15} className="shrink-0" aria-hidden="true" />
                <span className="flex-1">{saveMessage}</span>
                <button
                  type="button"
                  onClick={() => setSaveStatus('idle')}
                  className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={t('dismiss')}
                >
                  <X size={13} aria-hidden="true" />
                </button>
              </div>
            )}
          </div>
        </form>
      </SectionCard>

      <SectionCard title={t('adminManualCleanupTitle')} description={t('adminManualCleanupDesc')}>
        <div className="flex flex-col gap-3">
          <div>
            <Button size="sm" variant="outline" onClick={handleRun} disabled={runStatus === 'running'}>
              {runStatus === 'running'
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Play size={13} className="mr-1.5" aria-hidden="true" />}
              {t('adminRunCleanup')}
            </Button>
          </div>

          {runStatus === 'done' && runResult && (
            runResult.enabled ? (
              <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 dark:border-emerald-800 dark:bg-emerald-950">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-sm font-medium text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 size={15} aria-hidden="true" />
                    {t('adminCleanupDone')}
                  </div>
                  <button
                    type="button"
                    onClick={dismissRun}
                    className="shrink-0 rounded text-emerald-700 hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring dark:text-emerald-400"
                    aria-label={t('dismiss')}
                  >
                    <X size={13} aria-hidden="true" />
                  </button>
                </div>
                <ul className="mt-2 space-y-0.5 text-xs text-emerald-700 dark:text-emerald-400">
                  <li>{t('adminCleanupCompletedJobs')}: {runResult.completed_jobs_deleted} {t('adminCleanupRemoved')}</li>
                  <li>{t('adminCleanupFailedJobs')}: {runResult.failed_jobs_deleted} {t('adminCleanupRemoved')}</li>
                  <li>{t('adminCleanupCancelledJobs')}: {runResult.cancelled_jobs_deleted} {t('adminCleanupRemoved')}</li>
                  <li>{t('adminCleanupExpiredTokens')}: {runResult.tokens_deleted} {t('adminCleanupRemoved')}</li>
                  <li>{t('adminCleanupTempTorrents')}: {runResult.temp_files_deleted} {t('adminCleanupRemoved')}</li>
                </ul>
                {runResult.temp_files_errors.length > 0 && (
                  <ul className="mt-2 space-y-0.5 text-xs text-amber-700 dark:text-amber-400">
                    {runResult.temp_files_errors.map((msg, i) => (
                      <li key={i}>{msg}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : (
              <div className="flex items-start gap-3 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
                <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
                <span className="flex-1">{t('adminCleanupIsDisabled')}</span>
                <button
                  type="button"
                  onClick={dismissRun}
                  className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={t('dismiss')}
                >
                  <X size={13} aria-hidden="true" />
                </button>
              </div>
            )
          )}

          {runStatus === 'failed' && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{runError}</span>
              <button
                type="button"
                onClick={dismissRun}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  )
}
