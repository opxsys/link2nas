import { Search, RefreshCw, PlusCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { JOB_STATUS_OPTIONS } from './jobs.utils'
import type { JobsFilters } from './jobs.types'

const SELECT = 'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

interface JobsToolbarProps {
  filters: JobsFilters
  providers: string[]
  destinations: string[]
  hasActiveProvider: boolean | null
  onFilter: <K extends keyof JobsFilters>(key: K, value: JobsFilters[K]) => void
  onRefresh: () => void
}

export default function JobsToolbar({
  filters, providers, destinations, hasActiveProvider, onFilter, onRefresh,
}: JobsToolbarProps) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative min-w-[180px] flex-1">
        <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <input
          type="search"
          placeholder={t('searchJobsPlaceholder')}
          value={filters.search}
          onChange={(e) => onFilter('search', e.target.value)}
          className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          aria-label={t('ariaSearchJobs')}
        />
      </div>

      <select value={filters.status} onChange={(e) => onFilter('status', e.target.value)} className={SELECT} aria-label={t('ariaFilterStatus')}>
        <option value="">{t('allStatuses')}</option>
        {JOB_STATUS_OPTIONS.map(({ value, labelKey }) => <option key={value} value={value}>{t(labelKey)}</option>)}
      </select>

      <select value={filters.provider} onChange={(e) => onFilter('provider', e.target.value)} className={SELECT} aria-label={t('ariaFilterProvider')}>
        <option value="">{t('allProviders')}</option>
        {providers.map((p) => <option key={p} value={p}>{p}</option>)}
      </select>

      <select value={filters.destination} onChange={(e) => onFilter('destination', e.target.value)} className={SELECT} aria-label={t('ariaFilterDestination')}>
        <option value="">{t('allDestinations')}</option>
        {destinations.map((d) => <option key={d} value={d}>{d}</option>)}
      </select>

      <Button variant="outline" size="icon" onClick={onRefresh} aria-label={t('ariaRefreshJobs')}>
        <RefreshCw size={14} aria-hidden="true" />
      </Button>

      {hasActiveProvider === true && (
        <Button asChild size="sm">
          <Link to="/jobs/new">
            <PlusCircle size={14} aria-hidden="true" />
            {t('navNewJob')}
          </Link>
        </Button>
      )}
    </div>
  )
}
