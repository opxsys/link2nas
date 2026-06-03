import DashboardDefaultConfig from './DashboardDefaultConfig'
import DashboardStorage from './DashboardStorage'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'
import type { MaintenanceDisk } from '@/pages/Admin/admin.types'

interface Props {
  providers: ProviderConfig[] | null
  destinations: DestinationConfig[] | null
  disk: MaintenanceDisk | null
  loading: boolean
}

export default function DashboardConfigGrid({ providers, destinations, disk, loading }: Props) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <DashboardDefaultConfig providers={providers} destinations={destinations} loading={loading} />
      <DashboardStorage disk={disk} loading={loading} />
    </div>
  )
}
