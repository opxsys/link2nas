import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Settings, Loader2, AlertCircle, CheckCircle2, Info } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getProwlarrStatus, searchProwlarr } from '@/api/prowlarr'
import { useI18n } from '@/i18n'
import ProwlarrSearchForm from './ProwlarrSearchForm'
import ProwlarrResultList from './ProwlarrResultList'
import type { ProwlarrStatusResult, ProwlarrSearchResult } from '@/api/prowlarr'
import type { SearchStatus } from './prowlarr.types'

export default function Prowlarr() {
  const { t } = useI18n()
  const [statusLoading, setStatusLoading] = useState(true)
  const [prowlarrStatus, setProwlarrStatus] = useState<ProwlarrStatusResult | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)

  const [searchStatus, setSearchStatus] = useState<SearchStatus>('idle')
  const [results, setResults] = useState<ProwlarrSearchResult[]>([])
  const [searchError, setSearchError] = useState<string | null>(null)

  useEffect(() => {
    getProwlarrStatus()
      .then(setProwlarrStatus)
      .catch((err) => setStatusError(err instanceof Error ? err.message : t('prowlarrSearchError')))
      .finally(() => setStatusLoading(false))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleSearch(query: string) {
    setSearchStatus('searching')
    setSearchError(null)
    setResults([])
    try {
      const data = await searchProwlarr({ query })
      setResults(data.results)
      setSearchStatus('done')
    } catch (err) {
      setSearchError(err instanceof Error ? err.message : t('prowlarrSearchError'))
      setSearchStatus('error')
    }
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
                <ProwlarrSearchForm onSearch={handleSearch} searchStatus={searchStatus} />
                {searchStatus === 'error' && searchError && (
                  <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                    <AlertCircle size={14} className="shrink-0" aria-hidden="true" />
                    {searchError}
                  </div>
                )}
                {(searchStatus === 'done' || results.length > 0) && (
                  <ProwlarrResultList results={results} />
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
      {status.version && (
        <span className="tabular-nums">v{status.version}</span>
      )}
      {status.active_indexers != null && (
        <span className="tabular-nums">
          {status.active_indexers} {t('prowlarrIndexerCount')}
        </span>
      )}
    </div>
  )
}
