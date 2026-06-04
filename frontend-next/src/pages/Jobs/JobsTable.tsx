import { cn } from '@/lib/utils'
import StatusBadge from '@/components/status/StatusBadge'
import { displayValue } from './jobs.utils'
import { jobName, jobProvider, jobDestination, formatBytes } from './jobs.types'
import { EmptyNoProvider, EmptyNoJobs, EmptyFiltered } from './JobsEmptyState'
import type { RealJob } from '@/api/jobs'

interface JobsTableProps {
  jobs: RealJob[]
  totalJobs: number
  hasActiveProvider: boolean | null
  selectedJobId: string | null
  onSelect: (id: string) => void
  onClearFilters: () => void
  loading?: boolean
}

const TH = 'px-4 py-2.5 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-3'

export default function JobsTable({
  jobs, totalJobs, hasActiveProvider,
  selectedJobId, onSelect, onClearFilters, loading,
}: JobsTableProps) {
  if (loading) {
    return <div className="px-4 py-10 text-center text-sm text-muted-foreground">Loading jobs…</div>
  }

  if (jobs.length === 0) {
    if (hasActiveProvider === false) return <EmptyNoProvider />
    if (totalJobs === 0) return <EmptyNoJobs />
    return <EmptyFiltered onClearFilters={onClearFilters} />
  }

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
          {jobs.map((job) => (
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
                  <span className="block max-w-[220px] truncate font-medium text-foreground" title={jobName(job)}>
                    {jobName(job)}
                  </span>
                </td>
                <td className={TD}><StatusBadge status={job.status} /></td>
                <td className={cn(TD, 'hidden text-muted-foreground sm:table-cell')}>{jobProvider(job)}</td>
                <td className={cn(TD, 'hidden text-muted-foreground md:table-cell')}>
                  {displayValue(jobDestination(job), 'Links only')}
                </td>
                <td className={cn(TD, 'hidden text-right text-muted-foreground lg:table-cell')}>
                  {displayValue(job.files.length || null)}
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground lg:table-cell')}>
                  {formatBytes(job.filesize)}
                </td>
                <td className={cn(TD, 'hidden text-muted-foreground xl:table-cell')}>
                  {job.created_at ? new Date(job.created_at).toLocaleDateString() : '—'}
                </td>
              </tr>
          ))}
        </tbody>
      </table>
      <div className="border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
        {jobs.length} job{jobs.length !== 1 ? 's' : ''}
      </div>
    </div>
  )
}
