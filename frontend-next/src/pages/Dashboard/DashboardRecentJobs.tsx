import { Link } from 'react-router-dom'
import SectionCard from '@/components/common/SectionCard'
import StatusBadge from '@/components/status/StatusBadge'
import { MOCK_RECENT_JOBS } from './dashboard.mock'

export default function DashboardRecentJobs() {
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
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                Name
              </th>
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                Status
              </th>
              <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground sm:table-cell">
                Provider
              </th>
              <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground md:table-cell">
                Destination
              </th>
              <th className="hidden px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground lg:table-cell">
                Created
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {MOCK_RECENT_JOBS.map((job) => (
              <tr key={job.id} className="hover:bg-muted/40">
                <td className="px-4 py-3">
                  <span
                    className="block max-w-[200px] truncate font-medium text-foreground"
                    title={job.name}
                  >
                    {job.name}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={job.status} />
                </td>
                <td className="hidden px-4 py-3 text-muted-foreground sm:table-cell">
                  {job.provider}
                </td>
                <td className="hidden px-4 py-3 text-muted-foreground md:table-cell">
                  {job.destination ?? '—'}
                </td>
                <td className="hidden px-4 py-3 text-muted-foreground lg:table-cell">
                  {job.created}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
