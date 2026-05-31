import { useState } from 'react'
import { X, Copy, Send, Trash2, CircleMinus } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import StatusBadge from '@/components/status/StatusBadge'
import { displayValue } from './jobs.utils'
import JobFilesTable from './JobFilesTable'
import JobProgressCard from './JobProgressCard'
import type { JobDetails, JobDetailsTab } from './jobs.types'

interface JobDetailsSheetProps {
  job: JobDetails
  onClose: () => void
}

const TABS: { id: JobDetailsTab; label: string }[] = [
  { id: 'files', label: 'Files' },
  { id: 'links', label: 'Links' },
  { id: 'details', label: 'Details' },
  { id: 'logs', label: 'Logs' },
]

const DESTRUCTIVE_BTN =
  'border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive disabled:opacity-50 disabled:text-destructive/50'

export default function JobDetailsSheet({ job, onClose }: JobDetailsSheetProps) {
  const [activeTab, setActiveTab] = useState<JobDetailsTab>('files')

  return (
    <div className="flex flex-col">
      {/* Header */}
      <div className="flex items-start gap-3 border-b border-border p-4">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-foreground" title={job.name}>
            {job.name}
          </p>
          <div className="mt-1.5">
            <StatusBadge status={job.status} />
          </div>
        </div>
        <button
          onClick={onClose}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Close job details"
        >
          <X size={15} aria-hidden="true" />
        </button>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <Button variant="outline" size="sm" disabled>
          <Copy size={13} aria-hidden="true" />
          Copy Links
        </Button>
        <Button variant="outline" size="sm" disabled>
          <Send size={13} aria-hidden="true" />
          Send
        </Button>
        <div className="ml-auto">
          <Button variant="outline" size="sm" disabled className={DESTRUCTIVE_BTN}>
            <Trash2 size={13} aria-hidden="true" />
            Delete
          </Button>
        </div>
      </div>

      {/* Metadata */}
      <div className="space-y-2.5 border-b border-border p-4">
        {(
          [
            ['Provider', job.provider],
            ['Destination', displayValue(job.destination, 'Links only')],
            ['Files', displayValue(job.fileCount)],
            ['Size', displayValue(job.size)],
            ['Created', job.created],
          ] as [string, string][]
        ).map(([label, value]) => (
          <div key={label} className="flex gap-3">
            <span className="w-24 shrink-0 text-xs text-muted-foreground">{label}</span>
            <span className="min-w-0 truncate text-xs font-medium text-foreground">{value}</span>
          </div>
        ))}
        {job.jobPath && (
          <div className="flex gap-3">
            <span className="w-24 shrink-0 text-xs text-muted-foreground">Job ID</span>
            <span
              className="min-w-0 truncate font-mono text-xs text-muted-foreground"
              title={job.jobPath}
            >
              {job.jobPath}
            </span>
          </div>
        )}
      </div>

      {/* Tabs */}
      <nav className="flex shrink-0 border-b border-border" aria-label="Job detail sections">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={cn(
              'px-4 py-2.5 text-xs transition-colors',
              activeTab === id
                ? 'border-b-2 border-primary font-medium text-primary'
                : 'text-muted-foreground hover:text-foreground',
            )}
            aria-selected={activeTab === id}
          >
            {label}
          </button>
        ))}
      </nav>

      {/* Tab content */}
      {activeTab === 'files' && <JobFilesTable files={job.files} />}
      {activeTab === 'links' && (
        <p className="p-4 text-sm text-muted-foreground">Links — coming soon.</p>
      )}
      {activeTab === 'details' && (
        <p className="p-4 text-sm text-muted-foreground">Details — coming soon.</p>
      )}
      {activeTab === 'logs' && (
        <p className="p-4 text-sm text-muted-foreground">Logs — coming soon.</p>
      )}

      {/* Progress */}
      <JobProgressCard progress={job.progress} />

      {/* Destructive footer */}
      <div className="border-t border-border p-4">
        <Button variant="outline" size="sm" disabled className={DESTRUCTIVE_BTN}>
          <CircleMinus size={13} aria-hidden="true" />
          Cancel Job
        </Button>
      </div>
    </div>
  )
}
