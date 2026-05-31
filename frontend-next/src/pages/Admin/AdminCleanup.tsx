import { CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { CleanupStatus } from './admin.types'
import { MOCK_RETENTION } from './admin-settings.mock'

interface Props {
  cleanupStatus: CleanupStatus
  onRun: () => void
}

export default function AdminCleanup({ cleanupStatus, onRun }: Props) {
  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        title="Retention Rules"
        description="Automatic cleanup keeps the database lean by removing old records."
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Target</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Retain</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Last run</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Next run</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_RETENTION.map((rule) => (
                <tr key={rule.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="px-4 py-2.5 text-sm text-foreground">{rule.target}</td>
                  <td className="px-4 py-2.5 text-sm text-muted-foreground">{rule.retainDays} days</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{rule.lastRun ?? '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{rule.nextRun ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <SectionCard title="Manual Cleanup" description="Trigger an immediate cleanup run outside the schedule.">
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <Button size="sm" variant="outline" onClick={onRun} disabled={cleanupStatus === 'running'}>
              {cleanupStatus === 'running' && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              Run cleanup now
            </Button>
          </div>
          {cleanupStatus === 'done' && (
            <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2.5 text-sm text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
              <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
              Cleanup completed (mock) — old records removed.
            </div>
          )}
          {cleanupStatus === 'failed' && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={15} className="shrink-0" aria-hidden="true" />
              Cleanup failed (mock) — check system events for details.
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  )
}
