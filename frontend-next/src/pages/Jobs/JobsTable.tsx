import { cn } from '@/lib/utils'
import StatusBadge from '@/components/status/StatusBadge'
import { displayValue } from './jobs.utils'
import type { Job } from './jobs.types'

interface JobsTableProps {
  jobs: Job[]
  selectedJobId: string | null
  onSelect: (id: string) => void
}

const TH = 'px-4 py-2.5 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-3'

export default function JobsTable({ jobs, selectedJobId, onSelect }: JobsTableProps) {
  return (
    <div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/30">
            <th className={TH}>Name</th>
            <th className={TH}>Status</th>
            <th className={cn(TH, 'hidden sm:table-cell')}>Provider</th>
            <th className={cn(TH, 'hidden md:table-cell')}>Destination</th>
            <th className={cn(TH, 'hidden lg:table-cell')}>Files</th>
            <th className={cn(TH, 'hidden lg:table-cell')}>Size</th>
            <th className={cn(TH, 'hidden xl:table-cell')}>Created</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {jobs.length === 0 ? (
            <tr>
              <td
                colSpan={7}
                className="px-4 py-10 text-center text-sm text-muted-foreground"
              >
                No jobs match the current filters.
              </td>
            </tr>
          ) : (
            jobs.map((job) => (
              <tr
                key={job.id}
                onClick={() => onSelect(job.id)}
                className={cn(
                  'cursor-pointer transition-colors hover:bg-muted/40',
                  selectedJobId === job.id && 'bg-primary/5 hover:bg-primary/10',
                )}
                aria-selected={selectedJobId === job.id}
              >
                <td className={TD}>
                  <span
                    className="block max-w-[220px] truncate font-medium text-foreground"
                    title={job.name}
                  >
                    {job.name}
                  </span>
                </td>
                <td className={TD}>
                  <StatusBadge status={job.status} />
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground sm:table-cell')}>
                  {job.provider}
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground md:table-cell')}>
                  {displayValue(job.destination)}
                </td>
                <td className={cn(TD, 'hidden text-right text-muted-foreground lg:table-cell')}>
                  {displayValue(job.fileCount)}
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground lg:table-cell')}>
                  {displayValue(job.size)}
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground xl:table-cell')}>
                  {job.created}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      <div className="flex items-center justify-between border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
        <span>
          Showing {jobs.length > 0 ? 1 : 0}–{jobs.length} of {jobs.length} jobs
        </span>
        <div className="flex items-center gap-1">
          {[1, 2, 3].map((page) => (
            <button
              key={page}
              className={cn(
                'flex h-7 w-7 items-center justify-center rounded text-xs transition-colors',
                page === 1
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent',
              )}
              aria-label={`Page ${page}`}
              aria-current={page === 1 ? 'page' : undefined}
            >
              {page}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
