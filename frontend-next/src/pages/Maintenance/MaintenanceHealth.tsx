import { Globe, Database, HardDrive } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import ServiceStatusCard from '@/components/common/ServiceStatusCard'
import type { HealthStatus } from '@/lib/types'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import { formatBytes } from './maintenance.utils'

interface ServiceEntry {
  id: string
  name: string
  icon: LucideIcon
  status: HealthStatus
  statusLabel: string
  detail?: string
}

function buildServices(status: MaintenanceStatus): ServiceEntry[] {
  return [
    {
      id: 'app',
      name: 'Application',
      icon: Globe,
      status: 'ok',
      statusLabel: 'Running',
      detail: `${status.app.name} ${status.app.version}`,
    },
    {
      id: 'database',
      name: 'Database',
      icon: Database,
      status: status.database.ok ? 'ok' : 'error',
      statusLabel: status.database.ok ? 'Connected' : 'Error',
      detail: status.database.backend,
    },
    {
      id: 'disk',
      name: 'Disk',
      icon: HardDrive,
      status: status.disk.ok ? 'ok' : 'error',
      statusLabel: `${status.disk.percent_free}% free`,
      detail: `${formatBytes(status.disk.free_bytes)} available`,
    },
  ]
}

interface Props {
  status: MaintenanceStatus
}

export default function MaintenanceHealth({ status }: Props) {
  const services = buildServices(status)
  return (
    <SectionCard title="System Health">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {services.map((s) => (
          <ServiceStatusCard
            key={s.id}
            name={s.name}
            icon={s.icon}
            status={s.status}
            statusLabel={s.statusLabel}
            detail={s.detail}
          />
        ))}
      </div>
    </SectionCard>
  )
}
