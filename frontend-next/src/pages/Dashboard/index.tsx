import PageHeader from '@/components/layout/PageHeader'
import DashboardMetrics from './DashboardMetrics'
import DashboardSystemStatus from './DashboardSystemStatus'
import DashboardConfigGrid from './DashboardConfigGrid'
import DashboardRecentJobs from './DashboardRecentJobs'

export default function Dashboard() {
  return (
    <>
      <PageHeader title="Dashboard" description="System overview and recent activity." />
      <div className="space-y-6">
        <DashboardMetrics />
        <DashboardSystemStatus />
        <DashboardConfigGrid />
        <DashboardRecentJobs />
      </div>
    </>
  )
}
