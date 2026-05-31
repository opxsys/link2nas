import PageHeader from '@/components/layout/PageHeader'
import DashboardMetrics from './DashboardMetrics'
import DashboardConfigGrid from './DashboardConfigGrid'
import DashboardRecentJobs from './DashboardRecentJobs'

export default function Dashboard() {
  return (
    <>
      <PageHeader title="Dashboard" description="Activity overview and recent jobs." />
      <div className="space-y-6">
        <DashboardMetrics />
        <DashboardConfigGrid />
        <DashboardRecentJobs />
      </div>
    </>
  )
}
