import type { MockSubmission } from './prowlarr.types'

export const MOCK_SUBMISSIONS: MockSubmission[] = [
  {
    id: 's1',
    source: 'YTS',
    type: 'magnet',
    status: 'completed',
    jobId: '1',
    createdAt: '29/05/2026 10:12',
  },
  {
    id: 's2',
    source: 'RARBG',
    type: 'torrent',
    status: 'running',
    jobId: '7',
    createdAt: '29/05/2026 08:45',
  },
  {
    id: 's3',
    source: 'NZBGeek',
    type: 'magnet',
    status: 'failed',
    jobId: null,
    createdAt: '28/05/2026 22:30',
  },
  {
    id: 's4',
    source: 'YTS',
    type: 'torrent',
    status: 'completed',
    jobId: '3',
    createdAt: '28/05/2026 19:05',
  },
  {
    id: 's5',
    source: 'Nyaa',
    type: 'magnet',
    status: 'waiting',
    jobId: '6',
    createdAt: '28/05/2026 15:10',
  },
]

export const QBT_CLIENT_URL = 'http://link2nas.local:5000/api/qbt'
