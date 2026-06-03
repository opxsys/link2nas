import { Activity, Clock, CircleCheck, CircleX } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import type { ControlCenter } from '@/api/system'
import type { RealJob } from '@/api/jobs'

interface Props {
  controlCenter: ControlCenter | null
  jobs: RealJob[] | null
  loading: boolean
}

function isToday(dateStr: string | null | undefined): boolean {
  if (!dateStr) return false
  const d = new Date(dateStr)
  const now = new Date()
  return (
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  )
}

const ACTIVE_STATUSES = [
  'created', 'queued', 'waiting', 'starting', 'running',
  'downloading', 'sending', 'cancel_requested',
]

export default function DashboardMetrics({ controlCenter, jobs, loading }: Props) {
  const sc = controlCenter?.status_counts ?? {}
  const activeJobs  = ACTIVE_STATUSES.reduce((sum, s) => sum + (sc[s] ?? 0), 0)
  // queued + waiting only — created is already counted in activeJobs, so omit to avoid double-counting
  const waitingJobs = (sc.queued ?? 0) + (sc.waiting ?? 0)
  // completed_at is set when a job completes; failed jobs use updated_at (no failed_at field)
  const completedToday = jobs?.filter(j => isToday(j.completed_at)).length ?? 0
  const failedToday    = jobs?.filter(j => j.status === 'failed' && isToday(j.updated_at)).length ?? 0

  const fmt = (n: number) => loading ? '—' : n

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        label="Active Jobs"
        value={fmt(activeJobs)}
        icon={Activity}
        description="Running now"
        iconClassName="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
      />
      <MetricCard
        label="Waiting"
        value={fmt(waitingJobs)}
        icon={Clock}
        description="Queued"
        iconClassName="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
      />
      <MetricCard
        label="Completed Today"
        value={fmt(completedToday)}
        icon={CircleCheck}
        description="Since midnight"
        iconClassName="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
      />
      <MetricCard
        label="Failed Today"
        value={fmt(failedToday)}
        icon={CircleX}
        description="Since midnight"
        iconClassName="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
      />
    </div>
  )
}
