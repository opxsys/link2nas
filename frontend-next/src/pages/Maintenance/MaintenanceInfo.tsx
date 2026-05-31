import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_SYSTEM_INFO } from './maintenance.mock'

export default function MaintenanceInfo() {
  return (
    <SectionCard title="System Information">
      <dl className="divide-y divide-border">
        {MOCK_SYSTEM_INFO.map(({ key, value, available }) => (
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
