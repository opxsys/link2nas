import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, Download, Magnet, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createJobFromProwlarr } from '@/api/prowlarr'
import { useI18n } from '@/i18n'
import { formatBytes } from './prowlarr.utils'
import type { ProwlarrSearchResult } from '@/api/prowlarr'
import type { JobStatus } from './prowlarr.types'

interface Props {
  results: ProwlarrSearchResult[]
}

export default function ProwlarrResultList({ results }: Props) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [jobStates, setJobStates] = useState<Map<string, JobStatus>>(new Map())
  const [jobIds, setJobIds] = useState<Map<string, string>>(new Map())
  const [jobErrors, setJobErrors] = useState<Map<string, string>>(new Map())

  async function handleAdd(result: ProwlarrSearchResult) {
    setJobStates((prev) => new Map(prev).set(result.result_id, 'loading'))
    setJobErrors((prev) => { const m = new Map(prev); m.delete(result.result_id); return m })
    try {
      const job = await createJobFromProwlarr({ result_id: result.result_id })
      setJobIds((prev) => new Map(prev).set(result.result_id, job.id))
      if (job.started) {
        setJobStates((prev) => new Map(prev).set(result.result_id, 'ok'))
      } else {
        setJobStates((prev) => new Map(prev).set(result.result_id, 'partial_ok'))
        setJobErrors((prev) => new Map(prev).set(
          result.result_id,
          job.start_error ?? t('prowlarrAddJobFailed'),
        ))
      }
    } catch (err) {
      setJobStates((prev) => new Map(prev).set(result.result_id, 'error'))
      setJobErrors((prev) => new Map(prev).set(
        result.result_id,
        err instanceof Error ? err.message : t('prowlarrAddJobFailed'),
      ))
    }
  }

  function handleViewJob(jobId: string) {
    navigate('/jobs', { state: { selectedJobId: jobId } })
  }

  if (results.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">{t('prowlarrNoResults')}</p>
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/40 text-xs text-muted-foreground">
            <th className="px-3 py-2.5 text-left font-medium">{t('prowlarrResultTitle')}</th>
            <th className="hidden px-3 py-2.5 text-left font-medium sm:table-cell">{t('prowlarrResultIndexer')}</th>
            <th className="hidden px-3 py-2.5 text-right font-medium md:table-cell">{t('prowlarrResultSize')}</th>
            <th className="hidden px-3 py-2.5 text-right font-medium md:table-cell">{t('prowlarrResultSeeders')}</th>
            <th className="px-3 py-2.5 text-left font-medium">{t('prowlarrResultLinks')}</th>
            <th className="px-3 py-2.5 text-right font-medium">{t('prowlarrResultAdd')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {results.map((r) => {
            const state = jobStates.get(r.result_id) ?? 'idle'
            const jobId = jobIds.get(r.result_id)
            const errMsg = jobErrors.get(r.result_id)
            return (
              <tr key={r.result_id} className="hover:bg-muted/20">
                <td className="px-3 py-2.5">
                  <span className="line-clamp-2 max-w-xs text-foreground" title={r.title}>
                    {r.title}
                  </span>
                </td>
                <td className="hidden px-3 py-2.5 text-muted-foreground sm:table-cell">{r.indexer}</td>
                <td className="hidden px-3 py-2.5 text-right tabular-nums text-muted-foreground md:table-cell">
                  {formatBytes(r.size)}
                </td>
                <td className="hidden px-3 py-2.5 text-right tabular-nums text-muted-foreground md:table-cell">
                  {r.seeders ?? '—'}
                </td>
                <td className="px-3 py-2.5">
                  <LinkBadges result={r} />
                </td>
                <td className="px-3 py-2.5 text-right">
                  {state === 'ok' && jobId ? (
                    <button
                      type="button"
                      onClick={() => handleViewJob(jobId)}
                      className="inline-flex items-center gap-1 text-xs text-emerald-700 hover:underline dark:text-emerald-400"
                    >
                      <CheckCircle2 size={12} aria-hidden="true" />
                      {t('prowlarrGoToJob')}
                    </button>
                  ) : state === 'partial_ok' && jobId ? (
                    <div className="flex flex-col items-end gap-1">
                      <span className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                        <AlertCircle size={12} aria-hidden="true" />
                        {t('prowlarrJobNotStarted')}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleViewJob(jobId)}
                        className="text-xs text-muted-foreground hover:underline"
                      >
                        {t('prowlarrGoToJob')}
                      </button>
                    </div>
                  ) : state === 'error' ? (
                    <span
                      className="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400"
                      title={errMsg}
                    >
                      <XCircle size={12} aria-hidden="true" />
                      {t('prowlarrAddJobFailed')}
                    </span>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={state === 'loading' || (!r.has_download && !r.has_magnet)}
                      onClick={() => handleAdd(r)}
                    >
                      {state === 'loading'
                        ? <Loader2 size={12} className="animate-spin" aria-hidden="true" />
                        : t('prowlarrResultAddStart')}
                    </Button>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function LinkBadges({ result }: { result: ProwlarrSearchResult }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap gap-1">
      {result.has_magnet && (
        <span className="inline-flex items-center gap-0.5 rounded-full bg-violet-100 px-2 py-0.5 text-xs font-medium text-violet-700 dark:bg-violet-950 dark:text-violet-300">
          <Magnet size={10} aria-hidden="true" />
          {t('prowlarrMagnet')}
        </span>
      )}
      {result.has_download && (
        <span className="inline-flex items-center gap-0.5 rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-950 dark:text-blue-300">
          <Download size={10} aria-hidden="true" />
          {t('prowlarrDirect')}
        </span>
      )}
    </div>
  )
}
