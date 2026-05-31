import { Activity, CircleCheck, CircleX, BarChart3 } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import { MOCK_METRICS } from './dashboard.mock'

export default function DashboardMetrics() {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        label="Active Jobs"
        value={MOCK_METRICS.activeJobs}
        icon={Activity}
        description="Running now"
      />
      <MetricCard
        label="Completed Today"
        value={MOCK_METRICS.completedToday}
        icon={CircleCheck}
        description="Since midnight"
        iconClassName="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
      />
      <MetricCard
        label="Failed Today"
        value={MOCK_METRICS.failedToday}
        icon={CircleX}
        description="Since midnight"
        iconClassName="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
      />
      <MetricCard
        label="Total Jobs"
        value={MOCK_METRICS.totalJobs}
        icon={BarChart3}
        description="All time"
      />
    </div>
  )
}
