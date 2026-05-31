import { CheckCircle2, XCircle, Clock, Loader2, Magnet, FileArchive } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { MockSubmission, SubmissionStatus, SubmissionType } from './prowlarr.types'
import { MOCK_SUBMISSIONS } from './prowlarr.mock'

const STATUS_CONFIG: Record<SubmissionStatus, { label: string; icon: React.ReactNode; className: string }> = {
  completed: {
    label: 'Completed',
    icon: <CheckCircle2 size={13} aria-hidden="true" />,
    className: 'text-green-700 bg-green-50 border-green-200 dark:text-green-400 dark:bg-green-950 dark:border-green-800',
  },
  failed: {
    label: 'Failed',
    icon: <XCircle size={13} aria-hidden="true" />,
    className: 'text-red-700 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-950 dark:border-red-800',
  },
  waiting: {
    label: 'Waiting',
    icon: <Clock size={13} aria-hidden="true" />,
    className: 'text-yellow-700 bg-yellow-50 border-yellow-200 dark:text-yellow-400 dark:bg-yellow-950 dark:border-yellow-800',
  },
  running: {
    label: 'Running',
    icon: <Loader2 size={13} className="animate-spin" aria-hidden="true" />,
    className: 'text-blue-700 bg-blue-50 border-blue-200 dark:text-blue-400 dark:bg-blue-950 dark:border-blue-800',
  },
}

const TYPE_ICON: Record<SubmissionType, React.ReactNode> = {
  magnet: <Magnet size={13} className="text-muted-foreground" aria-hidden="true" />,
  torrent: <FileArchive size={13} className="text-muted-foreground" aria-hidden="true" />,
}

function StatusBadge({ status }: { status: SubmissionStatus }) {
  const s = STATUS_CONFIG[status]
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${s.className}`}>
      {s.icon}
      {s.label}
    </span>
  )
}

function SubmissionRow({ sub }: { sub: MockSubmission }) {
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 text-sm text-foreground">{sub.source}</td>
      <td className="px-4 py-2.5">
        <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground capitalize">
          {TYPE_ICON[sub.type]}
          {sub.type}
        </span>
      </td>
      <td className="px-4 py-2.5">
        <StatusBadge status={sub.status} />
      </td>
      <td className="px-4 py-2.5 text-sm">
        {sub.jobId ? (
          <a
            href="#"
            onClick={(e) => e.preventDefault()}
            className="text-primary underline-offset-2 hover:underline"
          >
            #{sub.jobId}
          </a>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">{sub.createdAt}</td>
    </tr>
  )
}

export default function ProwlarrRecentSubmissions() {
  return (
    <SectionCard title="Recent Submissions" description="Last external submissions received via the qBittorrent API.">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Source</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Type</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Status</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Job</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Created</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_SUBMISSIONS.map((sub) => (
              <SubmissionRow key={sub.id} sub={sub} />
            ))}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
