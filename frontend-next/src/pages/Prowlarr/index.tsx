import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Settings, Loader2, AlertCircle, CheckCircle2, Info } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getProwlarrStatus, getProwlarrIndexers, searchProwlarr } from '@/api/prowlarr'
import { useI18n } from '@/i18n'
import ProwlarrSearchForm from './ProwlarrSearchForm'
import ProwlarrSavedSearches from './ProwlarrSavedSearches'
import ProwlarrResultList from './ProwlarrResultList'
import { sortResults } from './prowlarr.utils'
import { loadSavedSearches, upsertSavedSearch, deleteSavedSearch } from './prowlarr.favorites'
import type { ProwlarrStatusResult, ProwlarrSearchResult, ProwlarrIndexer } from '@/api/prowlarr'
import type { SearchStatus, SearchFilters, SortState, SortField, SavedSearch } from './prowlarr.types'
import { DEFAULT_FILTERS, DEFAULT_SORT } from './prowlarr.types'

// desc = newest first / most seeders first for first click on those fields
const DESC_FIRST: SortField[] = ['seeders', 'age', 'size']

export default function Prowlarr() {
  const { t } = useI18n()

  const [statusLoading, setStatusLoading]   = useState(true)
  const [prowlarrStatus, setProwlarrStatus] = useState<ProwlarrStatusResult | null>(null)
  const [statusError, setStatusError]       = useState<string | null>(null)

  const [searchStatus, setSearchStatus]   = useState<SearchStatus>('idle')
  const [rawResults, setRawResults]       = useState<ProwlarrSearchResult[]>([])
  const [hasNext, setHasNext]             = useState(false)
  const [totalFiltered, setTotalFiltered] = useState<number | undefined>(undefined)
  const [searchError, setSearchError]     = useState<string | null>(null)
  const [indexers, setIndexers]         = useState<ProwlarrIndexer[]>([])

  const [filters, setFilters]     = useState<SearchFilters>(DEFAULT_FILTERS)
  const [sort, setSort]           = useState<SortState>(DEFAULT_SORT)
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(loadSavedSearches)
  const [page, setPage]         = useState(0)
  const [pageSize, setPageSize] = useState(25)

  // Period filtering and pagination are handled by the backend.
  // sortResults only sorts the current page.
  const displayedResults = useMemo(
    () => sortResults(rawResults, sort),
    [rawResults, sort],
  )

  useEffect(() => {
    getProwlarrStatus()
      .then((s) => {
        setProwlarrStatus(s)
        if (s.available) {
          getProwlarrIndexers().then(setIndexers).catch(() => {})
        }
      })
      .catch((err) => setStatusError(err instanceof Error ? err.message : t('prowlarrSearchError')))
      .finally(() => setStatusLoading(false))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function doSearch(p: number, sz: number) {
    const q          = filters.query.trim()
    const emptyQuery = !q
    const hasLimiter = filters.period !== 'all'
    if (emptyQuery && !hasLimiter) return  // defensive — form already blocks this
    setSearchStatus('searching')
    setSearchError(null)
    setRawResults([])
    setHasNext(false)
    setTotalFiltered(undefined)
    try {
      const data = await searchProwlarr({
        query:       q,
        period:      filters.period,
        categories:  filters.categories.length  > 0 ? filters.categories  : undefined,
        indexer_ids: filters.indexer_ids.length > 0 ? filters.indexer_ids : undefined,
        limit:  sz,
        offset: p * sz,
      })
      setRawResults(data.results)
      setHasNext(data.has_next ?? (data.results.length === sz))
      setTotalFiltered(data.total_filtered)
      setSearchStatus('done')
    } catch (err) {
      setSearchError(err instanceof Error ? err.message : t('prowlarrSearchError'))
      setSearchStatus('error')
    }
  }

  async function handleSearch() {
    setPage(0)
    await doSearch(0, pageSize)
  }

  async function handlePageChange(newPage: number) {
    setPage(newPage)
    await doSearch(newPage, pageSize)
  }

  async function handlePageSizeChange(newSize: number) {
    setPage(0)
    setPageSize(newSize)
    await doSearch(0, newSize)
  }

  function handleSort(field: SortField) {
    setSort((prev) =>
      prev.field === field
        ? { field, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { field, dir: DESC_FIRST.includes(field) ? 'desc' : 'asc' },
    )
  }

  function handleLoadSaved(s: SavedSearch) {
    setFilters(s.filters)
    setSort(s.sort)
  }

  function handleDeleteSaved(id: string) {
    setSavedSearches(deleteSavedSearch(id))
  }

  function handleSaveSearch(name: string) {
    setSavedSearches(upsertSavedSearch(name, filters, sort))
  }

  return (
    <>
      <PageHeader title={t('navProwlarr')} description={t('prowlarrDesc')} />

      <div className="flex flex-col gap-6">
        {statusLoading ? (
          <div className="flex items-center gap-2 py-12 text-muted-foreground">
            <Loader2 size={18} className="animate-spin" aria-hidden="true" />
            <span className="text-sm">{t('loading')}</span>
          </div>
        ) : statusError ? (
          <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>{statusError}</span>
          </div>
        ) : !prowlarrStatus?.available ? (
          <NotConfiguredState />
        ) : (
          <>
            <ConnectionBanner status={prowlarrStatus} />
            <SectionCard title={t('prowlarrSearchTitle')}>
              <div className="flex flex-col gap-4">
                <ProwlarrSearchForm
                  filters={filters}
                  onFiltersChange={setFilters}
                  onSearch={handleSearch}
                  searchStatus={searchStatus}
                  indexers={indexers}
                />
                <ProwlarrSavedSearches
                  saved={savedSearches}
                  onLoad={handleLoadSaved}
                  onDelete={handleDeleteSaved}
                  onSave={handleSaveSearch}
                />
                {searchStatus === 'error' && searchError && (
                  <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                    <AlertCircle size={14} className="shrink-0" aria-hidden="true" />
                    {searchError}
                  </div>
                )}
                {(searchStatus === 'done' || displayedResults.length > 0) && (
                  <ProwlarrResultList
                    results={displayedResults}
                    sort={sort}
                    onSort={handleSort}
                    page={page}
                    pageSize={pageSize}
                    hasNext={hasNext}
                    totalFiltered={totalFiltered}
                    onPageChange={handlePageChange}
                    onPageSizeChange={handlePageSizeChange}
                    searching={searchStatus === 'searching'}
                  />
                )}
              </div>
            </SectionCard>
          </>
        )}
      </div>
    </>
  )
}

function NotConfiguredState() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-border bg-muted/20 py-16 text-center">
      <Settings size={32} className="text-muted-foreground" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-foreground">{t('prowlarrNotConfigured')}</p>
        <p className="mt-1 text-xs text-muted-foreground">{t('prowlarrNotConfiguredDesc')}</p>
      </div>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings">
          <Settings size={13} className="mr-1.5" aria-hidden="true" />
          {t('goToSettingsProwlarr')}
        </Link>
      </Button>
    </div>
  )
}

function ConnectionBanner({ status }: { status: ProwlarrStatusResult }) {
  const { t } = useI18n()
  const isUser = status.source === 'user'
  const cls = isUser
    ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400'
    : 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400'
  const Icon = isUser ? CheckCircle2 : Info
  const label = isUser ? t('prowlarrApiSourceUser') : t('prowlarrApiSourceGlobal')
  return (
    <div className={`flex items-center gap-2 rounded-md border px-3 py-2.5 text-xs ${cls}`}>
      <Icon size={13} className="shrink-0" aria-hidden="true" />
      <span className="flex-1">{label}</span>
      {status.version && <span className="tabular-nums">v{status.version}</span>}
      {status.active_indexers != null && (
        <span className="tabular-nums">{status.active_indexers} {t('prowlarrIndexerCount')}</span>
      )}
    </div>
  )
}
