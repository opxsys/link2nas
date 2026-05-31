import { Link } from 'lucide-react'
import StatusBadge from '@/components/status/StatusBadge'
import UnavailableState from '@/components/common/UnavailableState'
import type { JobFile } from './jobs.types'

interface JobFilesTableProps {
  files: JobFile[]
}

const TH = 'px-4 py-2 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-2.5'

export default function JobFilesTable({ files }: JobFilesTableProps) {
  if (files.length === 0) {
    return (
      <UnavailableState
        message="No files available"
        note="File list will appear once the job starts processing."
        className="py-6"
      />
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border bg-muted/20">
            <th className={TH}>File</th>
            <th className={TH}>Size</th>
            <th className={TH}>Status</th>
            <th className={TH}>
              <span className="sr-only">Link</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {files.map((file) => (
            <tr key={file.id} className="hover:bg-muted/30">
              <td className={TD}>
                <span
                  className="block max-w-[180px] truncate text-xs font-medium text-foreground"
                  title={file.name}
                >
                  {file.name}
                </span>
              </td>
              <td className={`${TD} text-xs text-muted-foreground`}>{file.size}</td>
              <td className={TD}>
                <StatusBadge status={file.status} />
              </td>
              <td className={`${TD} text-right`}>
                <button
                  className="rounded text-muted-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-40"
                  aria-label={`Copy link for ${file.name}`}
                  disabled
                >
                  <Link size={13} aria-hidden="true" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
