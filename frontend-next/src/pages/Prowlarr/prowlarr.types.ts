export type ProwlarrOpenMode = 'iframe' | 'newtab'
export type ProwlarrConnectionStatus = 'connected' | 'disconnected' | 'unconfigured'
export type SubmissionType = 'magnet' | 'torrent'
export type SubmissionStatus = 'completed' | 'failed' | 'waiting' | 'running'
export type TestStatus = 'idle' | 'testing' | 'ok' | 'fail'

export interface ProwlarrConfig {
  enabled: boolean
  url: string
  openMode: ProwlarrOpenMode
  setAsHomePage: boolean
  connectionStatus: ProwlarrConnectionStatus
}

export interface MockSubmission {
  id: string
  source: string
  type: SubmissionType
  status: SubmissionStatus
  jobId: string | null
  createdAt: string
}
