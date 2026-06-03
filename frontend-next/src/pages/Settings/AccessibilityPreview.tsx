import StatusBadge from '@/components/status/StatusBadge'
import { Button } from '@/components/ui/button'
import type { JobStatus } from '@/lib/types'

const BADGE_STATUSES: JobStatus[] = ['completed', 'running', 'waiting', 'failed', 'created']

const SAMPLE_ROWS: { name: string; status: JobStatus; provider: string }[] = [
  { name: 'ubuntu-22.04.iso',    status: 'completed', provider: 'real-debrid' },
  { name: 'project-backup.tar',  status: 'running',   provider: 'alldebrid'   },
  { name: 'archive-2024.zip',    status: 'failed',    provider: 'real-debrid' },
]

export default function AccessibilityPreview() {
  return (
    <div className="flex flex-col gap-5">
      {/* Status badges */}
      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Status badges
        </p>
        <div className="flex flex-wrap gap-2">
          {BADGE_STATUSES.map((s) => (
            <StatusBadge key={s} status={s} />
          ))}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Each badge combines an icon, a text label, and a background colour — no information is conveyed by colour alone.
        </p>
      </div>

      {/* Buttons */}
      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Buttons
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm">Primary</Button>
          <Button size="sm" variant="outline">Outline</Button>
          <Button size="sm" variant="destructive">Destructive</Button>
          <Button size="sm" disabled>Disabled</Button>
        </div>
      </div>

      {/* Sample table */}
      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Sample job rows
        </p>
        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full text-xs">
            <thead className="border-b border-border bg-muted/40">
              <tr>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Name</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Provider</th>
              </tr>
            </thead>
            <tbody>
              {SAMPLE_ROWS.map((row, i) => (
                <tr
                  key={row.name}
                  className={i > 0 ? 'border-t border-border hover:bg-muted/20' : 'hover:bg-muted/20'}
                >
                  <td className="px-3 py-2 font-medium text-foreground">{row.name}</td>
                  <td className="px-3 py-2"><StatusBadge status={row.status} /></td>
                  <td className="px-3 py-2 text-muted-foreground">{row.provider}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
