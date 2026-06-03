import { AlertCircle, RefreshCw } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import DashboardMetrics from './DashboardMetrics'
import DashboardConfigGrid from './DashboardConfigGrid'
import DashboardRecentJobs from './DashboardRecentJobs'
import { useDashboardData } from './useDashboardData'

export default function Dashboard() {
  const data = useDashboardData()

  return (
    <>
      <PageHeader title="Dashboard" description="Activity overview and recent jobs." />

      {data.error && (
        <div className="mb-4 flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={16} className="mt-0.5 shrink-0" />
          <span className="flex-1">{data.error}</span>
          <Button size="sm" variant="outline" onClick={data.refresh} className="shrink-0 h-7 text-xs">
            <RefreshCw size={12} /> Retry
          </Button>
        </div>
      )}

      <div className="space-y-6">
        <DashboardMetrics
          controlCenter={data.controlCenter}
          jobs={data.jobs}
          loading={data.loading}
        />
        <DashboardConfigGrid
          providers={data.providers}
          destinations={data.destinations}
          disk={data.maintenance?.disk ?? null}
          loading={data.loading}
        />
        <DashboardRecentJobs jobs={data.jobs} loading={data.loading} />
      </div>
    </>
  )
}
