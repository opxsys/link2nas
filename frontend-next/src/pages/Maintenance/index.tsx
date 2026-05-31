import PageHeader from '@/components/layout/PageHeader'
import MaintenanceHealth from './MaintenanceHealth'
import MaintenanceInfo from './MaintenanceInfo'
import MaintenanceDirs from './MaintenanceDirs'
import MaintenanceActions from './MaintenanceActions'
import MaintenanceLogs from './MaintenanceLogs'

export default function Maintenance() {
  return (
    <>
      <PageHeader
        title="Maintenance"
        description="System health, diagnostics, and operational tools."
      />
      <div className="space-y-6">
        <MaintenanceHealth />
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <MaintenanceInfo />
          <MaintenanceDirs />
        </div>
        <MaintenanceActions />
        <MaintenanceLogs />
      </div>
    </>
  )
}
