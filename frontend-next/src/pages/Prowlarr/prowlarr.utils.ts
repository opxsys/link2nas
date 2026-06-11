import type { ProwlarrSearchResult } from '@/api/prowlarr'
import type { PeriodFilter, SortState } from './prowlarr.types'

export function formatCategories(cats: string[] | null | undefined): string {
  if (!cats || cats.length === 0) return '—'
  return cats.join(', ')
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || bytes <= 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

/** Returns a compact age string (e.g. "2h", "3d", "1y"). Returns '—' when date is absent or unparseable. */
export function formatAge(publishDate: string | null | undefined): string {
  if (!publishDate) return '—'
  const pub = new Date(publishDate).getTime()
  if (Number.isNaN(pub)) return '—'
  const diffMs = Date.now() - pub
  if (diffMs < 0) return '—'
  const mins = Math.floor(diffMs / 60_000)
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(diffMs / 3_600_000)
  if (hours < 24) return `${hours}h`
  const days = Math.floor(diffMs / 86_400_000)
  if (days < 365) return `${days}d`
  return `${Math.floor(days / 365)}y`
}

/**
 * Keeps results whose publish_date falls within the given period.
 * Results with no publish_date are always kept (no crash on missing data).
 */
export function filterByPeriod(
  results: ProwlarrSearchResult[],
  period: PeriodFilter,
): ProwlarrSearchResult[] {
  if (period === 'all') return results
  const now = Date.now()
  const cutoff =
    period === 'today' ? _startOfToday() :
    period === 'week'  ? now - 7  * 86_400_000 :
                         now - 30 * 86_400_000
  return results.filter((r) => {
    if (!r.publish_date) return true
    const t = new Date(r.publish_date).getTime()
    return !Number.isNaN(t) && t >= cutoff
  })
}

function _startOfToday(): number {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  return d.getTime()
}

/**
 * Returns a sorted copy of results.
 * Null values sort last regardless of sort direction.
 * 'age' asc = oldest first; 'age' desc = newest first.
 */
export function sortResults(
  results: ProwlarrSearchResult[],
  sort: SortState,
): ProwlarrSearchResult[] {
  const { field, dir } = sort
  const mul = dir === 'asc' ? 1 : -1
  return [...results].sort((a, b) => {
    switch (field) {
      case 'title':
        return mul * a.title.localeCompare(b.title)
      case 'indexer':
        return mul * a.indexer.localeCompare(b.indexer)
      case 'size': {
        if (a.size == null && b.size == null) return 0
        if (a.size == null) return 1
        if (b.size == null) return -1
        return mul * (a.size - b.size)
      }
      case 'seeders': {
        if (a.seeders == null && b.seeders == null) return 0
        if (a.seeders == null) return 1
        if (b.seeders == null) return -1
        return mul * (a.seeders - b.seeders)
      }
      case 'age': {
        const ta = a.publish_date ? new Date(a.publish_date).getTime() : null
        const tb = b.publish_date ? new Date(b.publish_date).getTime() : null
        if (ta === null && tb === null) return 0
        if (ta === null) return 1
        if (tb === null) return -1
        return mul * (ta - tb)
      }
      default:
        return 0
    }
  })
}
