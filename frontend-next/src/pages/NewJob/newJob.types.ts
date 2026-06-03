// 'magnet' = magnet links + direct URLs (one or more lines)
// 'torrent' = one or more .torrent files (sequential upload per file)
export type NewJobTab = 'magnet' | 'torrent'

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
