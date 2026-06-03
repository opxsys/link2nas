import { useState } from 'react'
import { X, Copy, CheckCircle2, Send, Trash2, Play, RefreshCcw, CircleX, Loader2, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import StatusBadge from '@/components/status/StatusBadge'
import JobFilesTable from './JobFilesTable'
import JobProgressCard from './JobProgressCard'
import { jobName, jobProvider, jobDestination, formatBytes } from './jobs.types'
import type { RealJob } from '@/api/jobs'

type Tab = 'files' | 'links' | 'details'
const TABS: { id: Tab; label: string }[] = [
  { id: 'files', label: 'Files' }, { id: 'links', label: 'Links' }, { id: 'details', label: 'Details' },
]

interface Props {
  job: RealJob
  actionPending: string | null
  actionError: string | null
  onClose: () => void
  onAction: (action: string, jobId: string) => Promise<void>
  onDeleteRequest: (jobId: string) => void
}

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false)
  function copy() { navigator.clipboard.writeText(text).catch(() => undefined); setCopied(true); setTimeout(() => setCopied(false), 2000) }
  return (
    <button onClick={copy} className="shrink-0 rounded text-muted-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={label} title="Copy">
      {copied ? <CheckCircle2 size={13} className="text-green-600" /> : <Copy size={13} />}
    </button>
  )
}

export default function JobDetailsSheet({ job, actionPending, actionError, onClose, onAction, onDeleteRequest }: Props) {
  const [tab, setTab] = useState<Tab>('files')
  const can = (a: string) => job.allowed_actions.includes(a)
  const busy = actionPending === job.id

  const allLinks: string[] = []
  if (job.download_url) allLinks.push(job.download_url)
  else job.output_links.forEach(l => { if (l.url) allLinks.push(l.url) })

  const progress = job.progress > 0 && job.progress < 100 ? {
    percent: job.progress, downloadedSize: null, speed: null, eta: null, connections: null, provider: job.provider_name,
  } : null

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-start gap-3 border-b border-border p-5">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-foreground" title={jobName(job)}>{jobName(job)}</p>
          <div className="mt-1.5"><StatusBadge status={job.status} /></div>
        </div>
        <button onClick={onClose} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="Close">
          <X size={15} aria-hidden="true" />
        </button>
      </div>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-4 py-3">
        {allLinks.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(allLinks.join('\n')).catch(() => undefined)}>
            <Copy size={13} aria-hidden="true" />{allLinks.length > 1 ? 'Copy all links' : 'Copy link'}
          </Button>
        )}
        {(can('send_to_destination') || can('resend')) && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction(can('resend') ? 'resend' : 'send_to_destination', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
            {can('resend') ? 'Resend' : 'Send'}
          </Button>
        )}
        {can('start') && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('start', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} Start
          </Button>
        )}
        {can('restart') && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('restart', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <RefreshCcw size={13} />} Restart
          </Button>
        )}
        {can('cancel') && (
          <Button variant="outline" size="sm" disabled={busy}
            className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
            onClick={() => onAction('cancel', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <CircleX size={13} />} Cancel
          </Button>
        )}
        <div className="ml-auto">
          <Button variant="outline" size="sm"
            className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
            onClick={() => onDeleteRequest(job.id)}>
            <Trash2 size={13} /> Delete
          </Button>
        </div>
      </div>

      {/* Action error */}
      {actionError && (
        <div className="flex items-start gap-2 border-b border-border bg-red-50 px-4 py-2.5 text-xs text-red-700 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={13} className="mt-0.5 shrink-0" />{actionError}
        </div>
      )}

      {/* Metadata */}
      <div className="space-y-2.5 border-b border-border p-5 text-xs">
        {([
          ['Provider',    jobProvider(job)],
          ['Destination', jobDestination(job) ?? 'Links only'],
          ['Files',       job.files.length ? String(job.files.length) : '—'],
          ['Size',        formatBytes(job.filesize)],
          ['Created',     job.created_at ? new Date(job.created_at).toLocaleString() : '—'],
        ] as [string, string][]).map(([label, value]) => (
          <div key={label} className="flex gap-3">
            <span className="w-24 shrink-0 text-muted-foreground">{label}</span>
            <span className="min-w-0 truncate font-medium text-foreground">{value}</span>
          </div>
        ))}
        <div className="flex gap-3">
          <span className="w-24 shrink-0 text-muted-foreground">ID</span>
          <span className="min-w-0 truncate font-mono text-muted-foreground">{job.id}</span>
        </div>
      </div>

      {/* Tabs */}
      <nav className="flex shrink-0 border-b border-border">
        {TABS.map(({ id, label }) => (
          <button key={id} onClick={() => setTab(id)}
            className={cn('px-4 py-2.5 text-xs transition-colors', tab === id ? 'border-b-2 border-primary font-medium text-primary' : 'text-muted-foreground hover:text-foreground')}
            aria-selected={tab === id}>{label}</button>
        ))}
      </nav>

      {/* Tab content */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {tab === 'files' && <JobFilesTable files={job.files} />}

        {tab === 'links' && (
          <div className="p-4">
            {allLinks.length === 0
              ? <p className="text-sm text-muted-foreground">No download links available yet.</p>
              : <ul className="flex flex-col gap-2">
                  {allLinks.map((url, i) => (
                    <li key={i} className="flex items-center gap-2 rounded-md border border-border bg-muted/20 px-3 py-2">
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">{url}</span>
                      <CopyBtn text={url} label={`Copy link ${i + 1}`} />
                    </li>
                  ))}
                </ul>}
          </div>
        )}

        {tab === 'details' && (
          <div className="space-y-3 p-5 text-xs">
            {job.error_message && (
              <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                <p className="mb-1 font-medium">Error</p>
                <p className="font-mono">{job.error_message}</p>
              </div>
            )}
            {([
              ['Send status',    job.destination_status],
              ['Destination msg',job.destination_message],
              ['Saved to',       job.destination_path],
              ['Started',        job.started_at ? new Date(job.started_at).toLocaleString() : null],
              ['Completed',      job.completed_at ? new Date(job.completed_at).toLocaleString() : null],
            ] as [string, string | null][])
              .filter(([, v]) => !!v)
              .map(([label, value]) => (
                <div key={label} className="flex gap-3">
                  <span className="w-32 shrink-0 text-muted-foreground">{label}</span>
                  <span className="min-w-0 truncate font-medium text-foreground">{value}</span>
                </div>
              ))}
          </div>
        )}
      </div>

      {progress && <JobProgressCard progress={progress} />}
    </div>
  )
}
