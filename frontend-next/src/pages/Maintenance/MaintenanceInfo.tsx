import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import { formatBytes } from './maintenance.utils'
import { useI18n } from '@/i18n'

interface InfoRow {
  key: string
  labelKey: string
  value: string
  available: boolean
}

interface Props {
  status: MaintenanceStatus
}

export default function MaintenanceInfo({ status }: Props) {
  const { t } = useI18n()

  const rows: InfoRow[] = [
    { key: 'appName',    labelKey: t('maintInfoAppName'),  value: status.app.name,           available: Boolean(status.app.name)           },
    { key: 'version',    labelKey: t('maintInfoVersion'),  value: status.app.version,        available: Boolean(status.app.version)        },
    { key: 'database',   labelKey: t('maintInfoDatabase'), value: status.database.backend,   available: Boolean(status.database.backend)   },
    {
      key: 'diskFree',
      labelKey: t('maintInfoDiskFree'),
      value: `${formatBytes(status.disk.free_bytes)} (${status.disk.percent_free}%)`,
      available: true,
    },
    {
      key: 'publicUrl',
      labelKey: t('maintInfoPublicUrl'),
      value: status.app.public_base_url || t('notConfigured'),
      available: Boolean(status.app.public_base_url),
    },
    { key: 'debug', labelKey: t('maintInfoDebug'), value: status.app.debug ? t('maintInfoOn') : t('maintInfoOff'), available: true },
  ]

  return (
    <SectionCard title={t('maintInfoTitle')}>
      <dl className="divide-y divide-border">
        {rows.map(({ key, labelKey, value, available }) => (
          <div
            key={key}
            className="flex items-baseline gap-4 py-2.5 first:pt-0 last:pb-0"
          >
            <dt className="w-28 shrink-0 text-xs font-medium text-muted-foreground">
              {labelKey}
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
