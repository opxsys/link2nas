import { Zap, Cpu, Clock, Database } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import ServiceStatusCard from '@/components/common/ServiceStatusCard'
import { MOCK_SYSTEM_SERVICES } from './dashboard.mock'

const SERVICE_ICONS: Record<string, LucideIcon> = {
  redis: Zap,
  worker: Cpu,
  scheduler: Clock,
  database: Database,
}

export default function DashboardSystemStatus() {
  return (
    <SectionCard title="System Status">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {MOCK_SYSTEM_SERVICES.map((service) => (
          <ServiceStatusCard
            key={service.id}
            name={service.name}
            icon={SERVICE_ICONS[service.id] ?? Database}
            status={service.status}
            statusLabel={service.statusLabel}
            detail={service.detail}
          />
        ))}
      </div>
    </SectionCard>
  )
}
