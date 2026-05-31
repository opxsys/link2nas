import { Search, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { JOB_STATUS_OPTIONS } from './jobs.utils'
import type { JobsFilters } from './jobs.types'

const SELECT_CLASS =
  'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

interface JobsToolbarProps {
  filters: JobsFilters
  providers: string[]
  destinations: string[]
  onFilter: <K extends keyof JobsFilters>(key: K, value: JobsFilters[K]) => void
}

export default function JobsToolbar({
  filters,
  providers,
  destinations,
  onFilter,
}: JobsToolbarProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative min-w-[180px] flex-1">
        <Search
          size={14}
          className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <input
          type="search"
          placeholder="Search jobs…"
          value={filters.search}
          onChange={(e) => onFilter('search', e.target.value)}
          className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          aria-label="Search jobs"
        />
      </div>

      <select
        value={filters.status}
        onChange={(e) => onFilter('status', e.target.value)}
        className={SELECT_CLASS}
        aria-label="Filter by status"
      >
        <option value="">All Statuses</option>
        {JOB_STATUS_OPTIONS.map(({ value, label }) => (
          <option key={value} value={value}>{label}</option>
        ))}
      </select>

      <select
        value={filters.provider}
        onChange={(e) => onFilter('provider', e.target.value)}
        className={SELECT_CLASS}
        aria-label="Filter by provider"
      >
        <option value="">All Providers</option>
        {providers.map((p) => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>

      <select
        value={filters.destination}
        onChange={(e) => onFilter('destination', e.target.value)}
        className={SELECT_CLASS}
        aria-label="Filter by destination"
      >
        <option value="">All Destinations</option>
        {destinations.map((d) => (
          <option key={d} value={d}>{d}</option>
        ))}
      </select>

      <Button variant="outline" size="icon" aria-label="Refresh jobs list">
        <RefreshCw size={14} aria-hidden="true" />
      </Button>
    </div>
  )
}
