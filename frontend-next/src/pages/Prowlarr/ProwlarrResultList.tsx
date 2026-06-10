import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertCircle, Download, Magnet, Info,
  CheckCircle2, XCircle, Loader2, ChevronUp, ChevronDown,
  ChevronLeft, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createJobFromProwlarr } from '@/api/prowlarr'
import { useI18n } from '@/i18n'
import { formatBytes, formatAge } from './prowlarr.utils'
import type { ProwlarrSearchResult } from '@/api/prowlarr'
import type { JobStatus, SortState, SortField } from './prowlarr.types'

const PAGE_SIZE_OPTIONS = [10, 25, 50]

interface Props {
  results: ProwlarrSearchResult[]
  sort: SortState
  onSort: (field: SortField) => void
  page: number
  pageSize: number
  rawCount: number
  onPageChange: (page: number) => void
  onPageSizeChange: (size: number) => void
  searching?: boolean
}

export default function ProwlarrResultList({
  results, sort, onSort,
  page, pageSize, rawCount,
  onPageChange, onPageSizeChange,
  searching,
}: Props) {
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

  const hasPrev = page > 0
  const hasNext = rawCount >= pageSize
  const TH = 'px-3 py-2.5 font-medium cursor-pointer select-none hover:text-foreground'

  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <div className="flex items-center border-b border-border bg-muted/20 px-3 py-1.5">
        <span className="text-xs text-muted-foreground">
          {results.length} {t('prowlarrResultsCount')}
        </span>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/40 text-xs text-muted-foreground">
            <SortTh field="title"   sort={sort} onSort={onSort} className={`${TH} text-left`}>
              {t('prowlarrResultTitle')}
            </SortTh>
            <SortTh field="age"     sort={sort} onSort={onSort} className={`hidden ${TH} text-right sm:table-cell`}>
              {t('prowlarrResultAge')}
            </SortTh>
            <SortTh field="indexer" sort={sort} onSort={onSort} className={`hidden ${TH} text-left md:table-cell`}>
              {t('prowlarrResultIndexer')}
            </SortTh>
            <SortTh field="size"    sort={sort} onSort={onSort} className={`hidden ${TH} text-right md:table-cell`}>
              {t('prowlarrResultSize')}
            </SortTh>
            <SortTh field="seeders" sort={sort} onSort={onSort} className={`hidden ${TH} text-right md:table-cell`}>
              {t('prowlarrResultSeeders')}
            </SortTh>
            <th className="px-3 py-2.5 text-left font-medium">{t('prowlarrResultLinks')}</th>
            <th className="px-3 py-2.5 text-right font-medium">{t('prowlarrResultAdd')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {results.map((r) => {
            const state  = jobStates.get(r.result_id) ?? 'idle'
            const jobId  = jobIds.get(r.result_id)
            const errMsg = jobErrors.get(r.result_id)
            const canAdd = r.has_real_magnet || r.has_torrent_download
            return (
              <tr key={r.result_id} className="hover:bg-muted/20">
                <td className="px-3 py-2.5">
                  <span className="line-clamp-2 max-w-xs text-foreground" title={r.title}>
                    {r.title}
                  </span>
                </td>
                <td className="hidden px-3 py-2.5 text-right tabular-nums text-muted-foreground sm:table-cell">
                  {formatAge(r.publish_date)}
                </td>
                <td className="hidden px-3 py-2.5 text-muted-foreground md:table-cell">{r.indexer}</td>
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
                    <button type="button" onClick={() => handleViewJob(jobId)}
                      className="inline-flex items-center gap-1 text-xs text-emerald-700 hover:underline dark:text-emerald-400">
                      <CheckCircle2 size={12} aria-hidden="true" />
                      {t('prowlarrGoToJob')}
                    </button>
                  ) : state === 'partial_ok' && jobId ? (
                    <div className="flex flex-col items-end gap-1">
                      <span className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                        <AlertCircle size={12} aria-hidden="true" />
                        {t('prowlarrJobNotStarted')}
                      </span>
                      <button type="button" onClick={() => handleViewJob(jobId)}
                        className="text-xs text-muted-foreground hover:underline">
                        {t('prowlarrGoToJob')}
                      </button>
                    </div>
                  ) : state === 'error' ? (
                    <span className="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400"
                      title={errMsg}>
                      <XCircle size={12} aria-hidden="true" />
                      {t('prowlarrAddJobFailed')}
                    </span>
                  ) : (
                    <Button size="sm" variant="outline"
                      disabled={state === 'loading' || !canAdd}
                      onClick={() => handleAdd(r)}>
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
      <div className="flex items-center justify-between border-t border-border bg-muted/20 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">{t('prowlarrPageSize')}</span>
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            disabled={searching}
            className="h-7 rounded border border-input bg-background px-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
          >
            {PAGE_SIZE_OPTIONS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={!hasPrev || searching}
            aria-label={t('prowlarrPagePrev')}
            className="inline-flex h-7 items-center gap-1 rounded border border-input bg-background px-2 text-xs text-foreground hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft size={12} aria-hidden="true" />
            {t('prowlarrPagePrev')}
          </button>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={!hasNext || searching}
            aria-label={t('prowlarrPageNext')}
            className="inline-flex h-7 items-center gap-1 rounded border border-input bg-background px-2 text-xs text-foreground hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {t('prowlarrPageNext')}
            <ChevronRight size={12} aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Subcomponents ──────────────────────────────────────────────────────────────

interface SortThProps {
  field: SortField
  sort: SortState
  onSort: (f: SortField) => void
  className: string
  children: React.ReactNode
}

function SortTh({ field, sort, onSort, className, children }: SortThProps) {
  const active = sort.field === field
  const Icon = active && sort.dir === 'asc' ? ChevronUp : ChevronDown
  return (
    <th className={className} onClick={() => onSort(field)}>
      <span className="inline-flex items-center gap-0.5">
        {children}
        <Icon size={10} aria-hidden="true" className={active ? 'text-primary' : 'opacity-40'} />
      </span>
    </th>
  )
}

function LinkBadges({ result }: { result: ProwlarrSearchResult }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap gap-1">
      {result.has_real_magnet && (
        <span className="inline-flex items-center gap-0.5 rounded-full bg-violet-100 px-2 py-0.5 text-xs font-medium text-violet-700 dark:bg-violet-950 dark:text-violet-300">
          <Magnet size={10} aria-hidden="true" />
          {t('prowlarrMagnet')}
        </span>
      )}
      {result.has_torrent_download && (
        <span className="inline-flex items-center gap-0.5 rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-950 dark:text-blue-300">
          <Download size={10} aria-hidden="true" />
          {t('prowlarrBadgeTorrent')}
        </span>
      )}
      {result.has_info_url && (
        <span className="inline-flex items-center gap-0.5 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
          <Info size={10} aria-hidden="true" />
          {t('prowlarrBadgeInfo')}
        </span>
      )}
    </div>
  )
}
