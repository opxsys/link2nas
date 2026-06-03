import { HardDrive } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import UnavailableState from '@/components/common/UnavailableState'
import type { MaintenanceDisk } from '@/pages/Admin/admin.types'

interface Props {
  disk: MaintenanceDisk | null
  loading: boolean
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B'
  const k = 1024
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1)
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${units[i]}`
}

function barColor(freePercent: number): string {
  if (freePercent >= 30) return 'bg-emerald-500'
  if (freePercent >= 10) return 'bg-amber-500'
  return 'bg-red-500'
}

export default function DashboardStorage({ disk, loading }: Props) {
  return (
    <SectionCard title="Storage">
      {loading ? (
        <p className="text-sm italic text-muted-foreground">Loading…</p>
      ) : !disk ? (
        <UnavailableState
          message="Storage info unavailable"
          note="Requires admin access to the maintenance endpoint."
          className="py-4"
        />
      ) : (
        <div>
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <HardDrive size={14} className="shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm font-medium text-foreground">{disk.path}</span>
            </div>
            <span className="shrink-0 text-xs text-muted-foreground">
              {disk.percent_free.toFixed(0)}% free
            </span>
          </div>

          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className={cn('h-full rounded-full transition-all', barColor(disk.percent_free))}
              style={{ width: `${Math.max(0, Math.min(100, disk.percent_free))}%` }}
              role="progressbar"
              aria-valuenow={disk.percent_free}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`${disk.path}: ${disk.percent_free.toFixed(0)}% free`}
            />
          </div>

          <div className="mt-1 flex justify-between text-xs text-muted-foreground">
            <span>{formatBytes(disk.used_bytes)} used</span>
            <span>{formatBytes(disk.free_bytes)} free</span>
          </div>

          {!disk.ok && disk.message && (
            <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">{disk.message}</p>
          )}
        </div>
      )}
    </SectionCard>
  )
}
