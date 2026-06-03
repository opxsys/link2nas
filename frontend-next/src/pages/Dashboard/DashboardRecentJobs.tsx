import { Link } from 'react-router-dom'
import SectionCard from '@/components/common/SectionCard'
import StatusBadge from '@/components/status/StatusBadge'
import UnavailableState from '@/components/common/UnavailableState'
import type { RealJob } from '@/api/jobs'

interface Props {
  jobs: RealJob[] | null
  loading: boolean
}

function jobDisplayName(job: RealJob): string {
  return job.filename || job.source_value || job.source_type || job.id
}

function jobProviderName(job: RealJob): string {
  return job.provider_name || job.provider_type || '—'
}

function jobDestinationName(job: RealJob): string | null {
  return job.destination_name || job.destination_type || null
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

const RECENT_LIMIT = 10

export default function DashboardRecentJobs({ jobs, loading }: Props) {
  const recent = jobs
    ? [...jobs]
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
        .slice(0, RECENT_LIMIT)
    : null

  return (
    <SectionCard
      title="Recent Jobs"
      actions={
        <Link to="/jobs" className="text-xs text-primary hover:underline">
          View all
        </Link>
      }
      bodyClassName="p-0"
    >
      {loading ? (
        <p className="px-4 py-6 text-sm italic text-muted-foreground">Loading…</p>
      ) : !recent || recent.length === 0 ? (
        <UnavailableState message="No jobs yet." className="py-6" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">Name</th>
                <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">Status</th>
                <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground sm:table-cell">Provider</th>
                <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground md:table-cell">Destination</th>
                <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground lg:table-cell">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {recent.map(job => {
                const name = jobDisplayName(job)
                const dest = jobDestinationName(job)
                return (
                  <tr key={job.id} className="hover:bg-muted/40">
                    <td className="px-4 py-3">
                      <span className="block max-w-[200px] truncate font-medium text-foreground" title={name}>
                        {name}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className="hidden px-4 py-3 text-muted-foreground sm:table-cell">
                      {jobProviderName(job)}
                    </td>
                    <td className="hidden px-4 py-3 text-muted-foreground md:table-cell">
                      {dest ?? '—'}
                    </td>
                    <td className="hidden px-4 py-3 text-muted-foreground lg:table-cell">
                      {formatDate(job.created_at)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  )
}
