import { useState, useEffect, useCallback, useRef } from 'react'
import { RefreshCw, Loader2, CheckCircle2, XCircle, AlertCircle, RotateCcw, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getAntiAbuse, resetAntiAbuseAll, resetAntiAbuseKind } from '@/api/admin-security'
import type { AntiAbuseStatus, AntiAbuseCounter } from './admin.types'
import { useI18n } from '@/i18n'

type ActionStatus = 'idle' | 'ok' | 'error'

function fmt(v: number | null | undefined): string {
  return v == null ? '—' : String(v)
}

function StatusBadge({ status }: { status: AntiAbuseCounter['status'] }) {
  return status === 'ok' ? (
    <span className="inline-flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-400">
      <CheckCircle2 size={12} aria-hidden="true" /> OK
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-xs text-amber-700 dark:text-amber-400">
      <AlertCircle size={12} aria-hidden="true" /> Unavailable
    </span>
  )
}

export default function AdminSecurityAntiAbuse() {
  const { t } = useI18n()
  const [data, setData] = useState<AntiAbuseStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [resettingKind, setResettingKind] = useState<string | null>(null)
  const [resettingAll, setResettingAll] = useState(false)
  const [actionStatus, setActionStatus] = useState<ActionStatus>('idle')
  const [actionMessage, setActionMessage] = useState('')
  const actionTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setData(await getAntiAbuse())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('adminLoadAntiAbuse'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleResetKind(kind: string) {
    if (actionTimer.current) clearTimeout(actionTimer.current)
    setResettingKind(kind)
    setActionStatus('idle')
    try {
      await resetAntiAbuseKind(kind)
      setActionStatus('ok')
      setActionMessage(`Counters for "${kind}" reset.`)
      actionTimer.current = setTimeout(() => setActionStatus('idle'), 4000)
      await load()
    } catch (err) {
      setActionStatus('error')
      setActionMessage(err instanceof Error ? err.message : t('resetFailed'))
    } finally {
      setResettingKind(null)
    }
  }

  async function handleResetAll() {
    if (actionTimer.current) clearTimeout(actionTimer.current)
    setResettingAll(true)
    setActionStatus('idle')
    try {
      await resetAntiAbuseAll()
      setActionStatus('ok')
      setActionMessage(t('adminAAAllReset'))
      actionTimer.current = setTimeout(() => setActionStatus('idle'), 4000)
      await load()
    } catch (err) {
      setActionStatus('error')
      setActionMessage(err instanceof Error ? err.message : t('resetFailed'))
    } finally {
      setResettingAll(false)
    }
  }

  const busy = resettingAll || resettingKind !== null

  return (
    <SectionCard title={t('adminAntiAbuseTitle')} description={t('adminAntiAbuseDesc')}>
      <div className="flex flex-col gap-4">
        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 size={15} className="animate-spin" aria-hidden="true" /> {t('loading')}
          </div>
        )}

        {fetchError && (
          <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
            <div>
              <p className="font-medium">{t('adminLoadAntiAbuse')}</p>
              <p className="mt-0.5 text-xs">{fetchError}</p>
              <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
            </div>
          </div>
        )}

        {data && (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-0.5 text-xs font-medium text-foreground">
                Backend: {data.backend}
              </span>
              {data.redis_enabled && (
                <span className="text-xs text-emerald-700 dark:text-emerald-400">Redis</span>
              )}
              <Button size="sm" variant="outline" disabled={busy || loading} onClick={load}>
                {loading
                  ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                  : <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />}
                {t('refresh')}
              </Button>
            </div>

            {data.note && (
              <p className="text-xs text-amber-700 dark:text-amber-400">{data.note}</p>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {[t('adminAAKind'), t('adminAALimit'), t('adminAAWindow'), t('adminAAActiveIds'), t('adminAAEstHits'), t('colStatus'), ''].map((h) => (
                      <th key={h} className="px-3 pb-2 pt-2 text-left text-xs font-medium text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data.counters.map((c) => (
                    <tr key={c.kind} className="hover:bg-muted/30">
                      <td className="px-3 py-2 text-xs font-medium text-foreground">{c.label}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{c.limit}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{c.window_seconds}s</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(c.active_identities)}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(c.estimated_hits)}</td>
                      <td className="px-3 py-2"><StatusBadge status={c.status} /></td>
                      <td className="px-3 py-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 px-2 text-xs"
                          disabled={busy}
                          onClick={() => handleResetKind(c.kind)}
                        >
                          {resettingKind === c.kind
                            ? <Loader2 size={11} className="animate-spin" aria-hidden="true" />
                            : t('adminAAReset')}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex flex-col gap-2">
              <div>
                <Button size="sm" variant="outline" disabled={busy} onClick={handleResetAll}>
                  {resettingAll
                    ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                    : <RotateCcw size={13} className="mr-1.5" aria-hidden="true" />}
                  {t('adminAAResetAll')}
                </Button>
              </div>
              {actionStatus === 'ok' && (
                <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
                  <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
                  <span className="flex-1">{actionMessage}</span>
                  <button type="button" onClick={() => { if (actionTimer.current) clearTimeout(actionTimer.current); setActionStatus('idle') }}
                    className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
                    <X size={13} aria-hidden="true" />
                  </button>
                </div>
              )}
              {actionStatus === 'error' && (
                <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                  <XCircle size={15} className="shrink-0" aria-hidden="true" />
                  <span className="flex-1">{actionMessage}</span>
                  <button type="button" onClick={() => setActionStatus('idle')}
                    className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
                    <X size={13} aria-hidden="true" />
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </SectionCard>
  )
}
