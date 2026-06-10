import type { ProwlarrSearchResult, ProwlarrStatusResult } from '@/api/prowlarr'

export type SearchStatus = 'idle' | 'searching' | 'done' | 'error'
export type JobStatus = 'idle' | 'loading' | 'ok' | 'partial_ok' | 'error'

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
