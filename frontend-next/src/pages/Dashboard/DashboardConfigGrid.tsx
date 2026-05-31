import DashboardDefaultConfig from './DashboardDefaultConfig'
import DashboardStorage from './DashboardStorage'

export default function DashboardConfigGrid() {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <DashboardDefaultConfig />
      <DashboardStorage />
    </div>
  )
}
