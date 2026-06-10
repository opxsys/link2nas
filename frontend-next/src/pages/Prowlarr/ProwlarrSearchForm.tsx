import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Search, Loader2, ChevronDown, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import { groupedCategories } from './prowlarr.categories'
import type { ProwlarrIndexer } from '@/api/prowlarr'
import type { SearchFilters, PeriodFilter, SearchStatus } from './prowlarr.types'

const INPUT_CLS = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'

interface Props {
  filters: SearchFilters
  onFiltersChange: (f: SearchFilters) => void
  onSearch: () => void
  searchStatus: SearchStatus
  indexers: ProwlarrIndexer[]
}

export default function ProwlarrSearchForm({
  filters, onFiltersChange, onSearch, searchStatus, indexers,
}: Props) {
  const { t } = useI18n()
  const searching  = searchStatus === 'searching'
  const [blockError, setBlockError] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const emptyQuery  = !filters.query.trim()
  const hasCats     = filters.categories.length > 0
  const hasIdxrs    = filters.indexer_ids.length > 0
  // Only period restricts scope enough to allow empty query — categories/indexers alone are too broad.
  const hasLimiter  = filters.period !== 'all'
  const canSearch   = !searching && (!emptyQuery || hasLimiter)
  const hasFilters  = filters.period !== 'all' || hasCats || hasIdxrs

  function setField<K extends keyof SearchFilters>(key: K, value: SearchFilters[K]) {
    if (blockError) setBlockError(false)
    onFiltersChange({ ...filters, [key]: value })
  }

  function toggleId(key: 'categories' | 'indexer_ids', id: number) {
    if (blockError) setBlockError(false)
    const arr = filters[key]
    onFiltersChange({
      ...filters,
      [key]: arr.includes(id) ? arr.filter((x) => x !== id) : [...arr, id],
    })
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!canSearch) {
      setBlockError(true)
      inputRef.current?.focus()
      return
    }
    setBlockError(false)
    onSearch()
  }

  const PERIOD_OPTIONS: { value: PeriodFilter; label: string }[] = [
    { value: 'all',   label: t('prowlarrPeriodAll') },
    { value: 'today', label: t('prowlarrPeriodToday') },
    { value: 'week',  label: t('prowlarrPeriodWeek') },
    { value: 'month', label: t('prowlarrPeriodMonth') },
  ]

  const enabledIndexers = indexers.filter((i) => i.enabled)
  const grouped = groupedCategories()

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      {/* Query row */}
      <div className="flex flex-col gap-1.5">
        <div className="flex gap-2">
          <input
            ref={inputRef}
            type="search"
            value={filters.query}
            onChange={(e) => setField('query', e.target.value)}
            placeholder={t('prowlarrSearchQueryPlaceholder')}
            disabled={searching}
            aria-label={t('prowlarrSearchQuery')}
            className={INPUT_CLS + ' flex-1'}
          />
          <Button type="submit" size="sm" disabled={!canSearch}>
            {searching
              ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
              : <Search size={13} className="mr-1.5" aria-hidden="true" />}
            {t('prowlarrSearchBtn')}
          </Button>
        </div>
        {blockError && (
          <p className="text-xs text-red-600 dark:text-red-400">
            {t('prowlarrSearchBlockedMsg')}
          </p>
        )}
        {!blockError && !searching && emptyQuery && (
          <p className="text-xs text-muted-foreground">
            {hasLimiter ? t('prowlarrSearchHintFiltered') : t('prowlarrSearchHintEmpty')}
          </p>
        )}
      </div>

      {/* Filter row */}
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={filters.period}
          onChange={(e) => setField('period', e.target.value as PeriodFilter)}
          disabled={searching}
          aria-label={t('prowlarrPeriodLabel')}
          className="h-8 rounded-md border border-input bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
        >
          {PERIOD_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        <FilterDropdown
          label={hasCats ? `${t('prowlarrCategoryLabel')} (${filters.categories.length})` : t('prowlarrCategoryAll')}
          active={hasCats}
          disabled={searching}
        >
          <div className="max-h-64 overflow-y-auto p-1">
            {Object.entries(grouped).map(([group, cats]) => (
              <div key={group}>
                <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {group}
                </p>
                {cats.map((cat) => (
                  <label key={cat.id} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs hover:bg-muted/60">
                    <input
                      type="checkbox"
                      checked={filters.categories.includes(cat.id)}
                      onChange={() => toggleId('categories', cat.id)}
                      className="h-3 w-3 accent-primary"
                    />
                    {cat.label}
                  </label>
                ))}
              </div>
            ))}
          </div>
        </FilterDropdown>

        <FilterDropdown
          label={hasIdxrs ? `${t('prowlarrIndexerLabel')} (${filters.indexer_ids.length})` : t('prowlarrIndexerAll')}
          active={hasIdxrs}
          disabled={searching}
        >
          {enabledIndexers.length === 0 ? (
            <p className="px-3 py-2 text-xs text-muted-foreground">{t('prowlarrIndexerLoading')}</p>
          ) : (
            <div className="max-h-48 overflow-y-auto p-1">
              {enabledIndexers.map((idx) => (
                <label key={idx.id} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs hover:bg-muted/60">
                  <input
                    type="checkbox"
                    checked={filters.indexer_ids.includes(idx.id)}
                    onChange={() => toggleId('indexer_ids', idx.id)}
                    className="h-3 w-3 accent-primary"
                  />
                  {idx.name}
                </label>
              ))}
            </div>
          )}
        </FilterDropdown>

        {hasFilters && (
          <button
            type="button"
            onClick={() => onFiltersChange({ ...filters, period: 'all', categories: [], indexer_ids: [] })}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:bg-muted/60 hover:text-foreground"
          >
            <X size={11} aria-hidden="true" />
            {t('prowlarrFiltersClear')}
          </button>
        )}
      </div>
    </form>
  )
}

// ── Internal: generic multi-select dropdown ───────────────────────────────────

interface DropdownProps {
  label: string
  active: boolean
  disabled?: boolean
  children: React.ReactNode
}

function FilterDropdown({ label, active, disabled, children }: DropdownProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => { if (!disabled) setOpen((v) => !v) }}
        disabled={disabled}
        className={[
          'inline-flex h-8 items-center gap-1 rounded-md border px-2.5 text-xs transition-colors',
          active
            ? 'border-primary bg-primary/10 text-primary'
            : 'border-input bg-background text-muted-foreground hover:text-foreground',
          disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
        ].join(' ')}
      >
        {label}
        <ChevronDown
          size={11}
          aria-hidden="true"
          className={open ? 'rotate-180 transition-transform' : 'transition-transform'}
        />
      </button>
      {open && (
        <div className="absolute left-0 top-9 z-50 min-w-44 rounded-md border border-border bg-popover shadow-md">
          {children}
        </div>
      )}
    </div>
  )
}
