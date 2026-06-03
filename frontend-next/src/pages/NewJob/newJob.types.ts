export type NewJobTab = 'magnet' | 'torrent' | 'batch'

export interface NewJobResultItem {
  id: string
  input: string
  status: 'created' | 'failed' | 'reused'
  jobId?: string
  error?: string
}

export interface NewJobResult {
  submitted: number
  created: number
  failed: number
  items: NewJobResultItem[]
}
