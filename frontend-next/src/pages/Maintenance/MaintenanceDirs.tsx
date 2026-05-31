import { CircleCheck, CircleX, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_DIRECTORIES } from './maintenance.mock'
import type { DirStatus } from './maintenance.mock'

const STATUS_ICON: Record<DirStatus, typeof CircleCheck> = {
  ok: CircleCheck,
  error: CircleX,
  unknown: AlertCircle,
}

const STATUS_CLASS: Record<DirStatus, string> = {
  ok: 'text-emerald-600 dark:text-emerald-400',
  error: 'text-red-600 dark:text-red-400',
  unknown: 'text-amber-600 dark:text-amber-400',
}

const STATUS_LABEL: Record<DirStatus, string> = {
  ok: 'OK',
  error: 'Error',
  unknown: 'Unknown',
}

export default function MaintenanceDirs() {
  return (
    <SectionCard title="Directory Checks" bodyClassName="p-0">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                Directory
              </th>
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                Path
              </th>
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {MOCK_DIRECTORIES.map((dir) => {
              const Icon = STATUS_ICON[dir.status]
              return (
                <tr key={dir.path} className="hover:bg-muted/40">
                  <td className="px-4 py-2.5 font-medium text-foreground">
                    {dir.label}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                    {dir.path}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={cn(
                        'flex items-center gap-1.5 text-xs font-medium',
                        STATUS_CLASS[dir.status],
                      )}
                    >
                      <Icon size={14} aria-hidden="true" />
                      {STATUS_LABEL[dir.status]}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
