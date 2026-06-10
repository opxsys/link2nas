import type { ProwlarrSearchResult, ProwlarrStatusResult } from '@/api/prowlarr'

export type SearchStatus = 'idle' | 'searching' | 'done' | 'error'
export type JobStatus = 'idle' | 'loading' | 'ok' | 'partial_ok' | 'error'

export type PeriodFilter = 'today' | 'week' | 'month' | 'all'
export type SortField = 'title' | 'age' | 'indexer' | 'size' | 'seeders'
export type SortDir = 'asc' | 'desc'

export interface SortState {
  field: SortField
  dir: SortDir
}

export interface SearchFilters {
  query: string
  period: PeriodFilter
  categories: number[]
  indexer_ids: number[]
}

export const DEFAULT_FILTERS: SearchFilters = {
  query: '',
  period: 'all',
  categories: [],
  indexer_ids: [],
}

export const DEFAULT_SORT: SortState = { field: 'age', dir: 'desc' }

export interface SavedSearch {
  id: string
  name: string
  filters: SearchFilters
  sort: SortState
  saved_at: string
}

export interface SearchState {
  status: SearchStatus
  results: ProwlarrSearchResult[]
  source: 'user' | 'global' | null
  errorMessage: string | null
}

export interface ProwlarrPageState {
  statusLoading: boolean
  prowlarrStatus: ProwlarrStatusResult | null
  statusError: string | null
}
