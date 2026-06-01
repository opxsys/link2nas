import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import { formatBytes } from './maintenance.utils'

interface InfoRow {
  key: string
  value: string
  available: boolean
}

function buildInfoRows(status: MaintenanceStatus): InfoRow[] {
  return [
    { key: 'App name', value: status.app.name, available: Boolean(status.app.name) },
    { key: 'Version', value: status.app.version, available: Boolean(status.app.version) },
    { key: 'Database', value: status.database.backend, available: Boolean(status.database.backend) },
    {
      key: 'Disk free',
      value: `${formatBytes(status.disk.free_bytes)} (${status.disk.percent_free}%)`,
      available: true,
    },
    {
      key: 'Public URL',
      value: status.app.public_base_url || 'Not configured',
      available: Boolean(status.app.public_base_url),
    },
    { key: 'Debug', value: status.app.debug ? 'On' : 'Off', available: true },
  ]
}

interface Props {
  status: MaintenanceStatus
}

export default function MaintenanceInfo({ status }: Props) {
  const rows = buildInfoRows(status)
  return (
    <SectionCard title="System Information">
      <dl className="divide-y divide-border">
        {rows.map(({ key, value, available }) => (
          <div
            key={key}
            className="flex items-baseline gap-4 py-2.5 first:pt-0 last:pb-0"
          >
            <dt className="w-28 shrink-0 text-xs font-medium text-muted-foreground">
              {key}
            </dt>
            <dd
              className={cn(
                'min-w-0 truncate text-sm',
                available ? 'text-foreground' : 'italic text-muted-foreground',
              )}
            >
              {value}
            </dd>
          </div>
        ))}
      </dl>
    </SectionCard>
  )
}
