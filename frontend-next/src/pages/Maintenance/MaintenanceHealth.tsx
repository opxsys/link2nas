import { Globe, Database, HardDrive } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import ServiceStatusCard from '@/components/common/ServiceStatusCard'
import type { HealthStatus } from '@/lib/types'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import { formatBytes } from './maintenance.utils'
import { useI18n } from '@/i18n'

interface ServiceEntry {
  id: string
  name: string
  icon: LucideIcon
  status: HealthStatus
  statusLabel: string
  detail?: string
}

interface Props {
  status: MaintenanceStatus
}

export default function MaintenanceHealth({ status }: Props) {
  const { t } = useI18n()

  const services: ServiceEntry[] = [
    {
      id: 'app',
      name: t('maintAppService'),
      icon: Globe,
      status: 'ok',
      statusLabel: t('maintRunning'),
      detail: `${status.app.name} ${status.app.version}`,
    },
    {
      id: 'database',
      name: t('maintDbService'),
      icon: Database,
      status: status.database.ok ? 'ok' : 'error',
      statusLabel: status.database.ok ? t('maintConnected') : t('maintError'),
      detail: status.database.backend,
    },
    {
      id: 'disk',
      name: t('maintDiskService'),
      icon: HardDrive,
      status: status.disk.ok ? 'ok' : 'error',
      statusLabel: `${status.disk.percent_free}% free`,
      detail: `${formatBytes(status.disk.free_bytes)} available`,
    },
  ]

  return (
    <SectionCard title={t('maintHealthTitle')}>
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
