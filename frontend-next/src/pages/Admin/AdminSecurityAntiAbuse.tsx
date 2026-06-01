import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, Loader2, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getAntiAbuse, resetAntiAbuseAll, resetAntiAbuseKind } from '@/api/admin-security'
import type { AntiAbuseStatus, AntiAbuseCounter } from './admin.types'

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
  const [data, setData] = useState<AntiAbuseStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [resettingKind, setResettingKind] = useState<string | null>(null)
  const [resettingAll, setResettingAll] = useState(false)
  const [actionStatus, setActionStatus] = useState<ActionStatus>('idle')
  const [actionMessage, setActionMessage] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setData(await getAntiAbuse())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load anti-abuse data.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleResetKind(kind: string) {
    setResettingKind(kind)
    setActionStatus('idle')
    try {
      await resetAntiAbuseKind(kind)
      setActionStatus('ok')
      setActionMessage(`Counters for "${kind}" reset.`)
      await load()
    } catch (err) {
      setActionStatus('error')
      setActionMessage(err instanceof Error ? err.message : 'Reset failed.')
    } finally {
      setResettingKind(null)
    }
  }

  async function handleResetAll() {
    setResettingAll(true)
    setActionStatus('idle')
    try {
      await resetAntiAbuseAll()
      setActionStatus('ok')
      setActionMessage('All anti-abuse counters reset.')
      await load()
    } catch (err) {
      setActionStatus('error')
      setActionMessage(err instanceof Error ? err.message : 'Reset all failed.')
    } finally {
      setResettingAll(false)
    }
  }

  const busy = resettingAll || resettingKind !== null

  return (
    <SectionCard title="Anti-Abuse / Rate Limits" description="Live rate-limit counters. Reset to unblock locked identities.">
      <div className="flex flex-col gap-4">
        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 size={15} className="animate-spin" aria-hidden="true" /> Loading…
          </div>
        )}

        {fetchError && (
          <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <AlertCircle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            <div>
              {fetchError}
              <Button size="sm" variant="outline" className="ml-3" onClick={load}>Retry</Button>
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
              <Button size="sm" variant="outline" disabled={busy} onClick={load}>
                <RefreshCw size={13} className="mr-1.5" aria-hidden="true" /> Refresh
              </Button>
            </div>

            {data.note && (
              <p className="text-xs text-amber-700 dark:text-amber-400">{data.note}</p>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {['Kind', 'Limit', 'Window', 'Active IDs', 'Est. Hits', 'Status', ''].map((h) => (
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
                            : 'Reset'}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Button size="sm" variant="outline" disabled={busy} onClick={handleResetAll}>
                {resettingAll
                  ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                  : <XCircle size={13} className="mr-1.5" aria-hidden="true" />}
                Reset all counters
              </Button>
              {actionStatus === 'ok' && (
                <span className="flex items-center gap-1.5 text-sm text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 size={14} aria-hidden="true" /> {actionMessage}
                </span>
              )}
              {actionStatus === 'error' && (
                <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
                  <XCircle size={14} aria-hidden="true" /> {actionMessage}
                </span>
              )}
            </div>
          </>
        )}
      </div>
    </SectionCard>
  )
}
