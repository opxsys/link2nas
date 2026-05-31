import { HardDrive } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_STORAGE } from './dashboard.mock'

function barColorClass(freePercent: number): string {
  if (freePercent >= 30) return 'bg-emerald-500'
  if (freePercent >= 10) return 'bg-amber-500'
  return 'bg-red-500'
}

export default function DashboardStorage() {
  return (
    <SectionCard title="Storage">
      <div className="space-y-5">
        {MOCK_STORAGE.map((item) => (
          <div key={item.id}>
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <HardDrive
                  size={14}
                  className="shrink-0 text-muted-foreground"
                  aria-hidden="true"
                />
                <span className="text-sm font-medium text-foreground">{item.label}</span>
              </div>
              <span className="shrink-0 text-xs text-muted-foreground">
                {item.freePercent}% free
              </span>
            </div>

            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={cn('h-full rounded-full transition-all', barColorClass(item.freePercent))}
                style={{ width: `${item.freePercent}%` }}
                role="progressbar"
                aria-valuenow={item.freePercent}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={`${item.label}: ${item.freePercent}% free`}
              />
            </div>

            <div className="mt-1 flex justify-between text-xs text-muted-foreground">
              <span>{item.usedLabel}</span>
              <span>{item.freeLabel}</span>
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  )
}
