import { Globe, Database, Zap, HardDrive, Cpu } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import ServiceStatusCard from '@/components/common/ServiceStatusCard'
import { MOCK_HEALTH_SERVICES } from './maintenance.mock'

const SERVICE_ICONS: Record<string, LucideIcon> = {
  app: Globe,
  database: Database,
  redis: Zap,
  disk: HardDrive,
  worker: Cpu,
}

export default function MaintenanceHealth() {
  return (
    <SectionCard title="System Health">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {MOCK_HEALTH_SERVICES.map((service) => (
          <ServiceStatusCard
            key={service.id}
            name={service.name}
            icon={SERVICE_ICONS[service.id] ?? Globe}
            status={service.status}
            statusLabel={service.statusLabel}
            detail={service.detail}
          />
        ))}
      </div>
    </SectionCard>
  )
}
