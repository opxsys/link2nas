export type NewJobTab = 'magnet' | 'torrent' | 'batch'

export interface MockProvider {
  id: string
  name: string
}

export interface MockDestination {
  id: string
  name: string
}

export interface NewJobResultItem {
  id: string
  input: string
  status: 'created' | 'failed'
  jobId?: string
  error?: string
}

export interface NewJobResult {
  submitted: number
  created: number
  failed: number
  items: NewJobResultItem[]
}
