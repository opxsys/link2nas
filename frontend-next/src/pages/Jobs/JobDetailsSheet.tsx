import { useState, useEffect } from 'react'
import {
  X, Copy, CheckCircle2, Send, Trash2, Play, RefreshCcw, CircleX,
  Loader2, AlertCircle, Link as LinkIcon, Unlock, RefreshCw,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import StatusBadge from '@/components/status/StatusBadge'
import JobFilesTable from './JobFilesTable'
import JobProgressCard from './JobProgressCard'
import { jobName, jobProvider, jobDestination, formatBytes } from './jobs.types'
import { getJobCapabilities } from './JobCapabilities'
import type { RealJob, RealJobDestinationConfig, RealJobProviderConfig } from '@/api/jobs'

type Tab = 'summary' | 'destination' | 'files' | 'links' | 'technical'
const TABS: { id: Tab; label: string }[] = [
  { id: 'summary',     label: 'Summary'     },
  { id: 'destination', label: 'Destination' },
  { id: 'files',       label: 'Files'       },
  { id: 'links',       label: 'Links'       },
  { id: 'technical',   label: 'Technical'   },
]

interface Props {
  job: RealJob
  actionPending: string | null
  actionError: string | null
  onClose: () => void
  onAction: (action: string, jobId: string, payload?: { destination_config_id?: string; provider_config_id?: string; file_id?: string | number }) => Promise<void>
  onDeleteRequest: (jobId: string) => void
}

function CopyBtn({ text, label, small }: { text: string; label: string; small?: boolean }) {
  const [done, setDone] = useState(false)
  function copy() { navigator.clipboard.writeText(text).catch(() => undefined); setDone(true); setTimeout(() => setDone(false), 2000) }
  return (
    <button onClick={copy} className={cn('shrink-0 rounded text-muted-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', small && 'p-0.5')} aria-label={label} title="Copy">
      {done ? <CheckCircle2 size={small ? 12 : 14} className="text-green-600" /> : <Copy size={small ? 12 : 14} />}
    </button>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (!value && value !== 0) return null
  return (
    <div className="flex gap-3 text-xs">
      <span className="w-32 shrink-0 text-muted-foreground">{label}</span>
      <span className="min-w-0 flex-1 font-medium text-foreground">{value}</span>
    </div>
  )
}

function ProgressBar({ percent, colorClass }: { percent: number; colorClass?: string }) {
  const pct = Math.max(0, Math.min(100, percent))
  const cls = colorClass ?? (pct >= 100 ? 'bg-emerald-500' : pct === 0 ? 'bg-muted-foreground/30' : 'bg-primary')
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
      <div className={cn('h-full rounded-full transition-all', cls)} style={{ width: `${pct}%` }}
        role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} />
    </div>
  )
}

interface SelectItemProps<T> { items: T[]; onSelect: (item: T) => void; onCancel: () => void; title: string; labelFn: (item: T) => string }
function InlineSelector<T extends { id: string }>({ items, onSelect, onCancel, title, labelFn }: SelectItemProps<T>) {
  const [chosen, setChosen] = useState(items[0]?.id ?? '')
  return (
    <div className="rounded-md border border-border bg-muted/30 p-3 text-xs">
      <p className="mb-2 font-medium text-foreground">{title}</p>
      <select value={chosen} onChange={e => setChosen(e.target.value)} className="mb-2 h-8 w-full rounded border border-input bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
        {items.map(item => <option key={item.id} value={item.id}>{labelFn(item)}</option>)}
      </select>
      <div className="flex gap-2">
        <Button size="sm" className="h-7 text-xs" onClick={() => { const item = items.find(i => i.id === chosen); if (item) onSelect(item) }}>Confirm</Button>
        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

export default function JobDetailsSheet({ job, actionPending, actionError, onClose, onAction, onDeleteRequest }: Props) {
  const [tab, setTab] = useState<Tab>('summary')
  const [showDestSelector, setShowDestSelector] = useState<'send' | 'other' | null>(null)
  const [showProvSelector, setShowProvSelector] = useState(false)

  const cap = getJobCapabilities(job)
  const busy = actionPending === job.id

  // Reset tab and close all selectors when the selected job changes
  useEffect(() => {
    setShowDestSelector(null)
    setShowProvSelector(false)
    setTab('summary')
  }, [job.id])

  const allLinks: string[] = []
  if (job.download_url) allLinks.push(job.download_url)
  else job.output_links.forEach(l => { if (l.url) allLinks.push(l.url) })

  // Sticky progress card: show for actively downloading jobs
  const activeStatuses = ['started', 'downloading', 'waiting_files_selection', 'downloaded']
  const stickyProgress = activeStatuses.includes(job.status)
    ? { percent: job.progress ?? 0, downloadedSize: null, speed: null, eta: null, connections: null, provider: job.provider_name }
    : null

  const showLinksHint = allLinks.length > 0

  function destLabel(d: RealJobDestinationConfig) { return d.name || d.destination_type || d.id }
  function provLabel(p: RealJobProviderConfig) { return p.name || p.provider_type || p.id }

  async function handleSendDirect() {
    setShowProvSelector(false)
    if (cap.activeDestinations.length > 1) { setShowDestSelector('send'); return }
    setTab('destination')
    await onAction('send_to_destination', job.id, { destination_config_id: cap.activeDestinations[0]?.id })
  }

  async function handleResend() {
    setTab('destination')
    await onAction('resend', job.id, { destination_config_id: job.destination_config_id ?? undefined })
  }

  async function handleSendOther() {
    setShowProvSelector(false)
    const alts = cap.activeDestinations.filter(d => d.id !== job.destination_config_id)
    if (alts.length === 1) { setTab('destination'); await onAction('send_to_destination', job.id, { destination_config_id: alts[0].id }); return }
    setShowDestSelector('other')
  }

  async function handleClone() {
    setShowDestSelector(null)
    if (cap.otherProviders.length === 1) { await onAction('clone_with_provider', job.id, { provider_config_id: cap.otherProviders[0].id }); return }
    setShowProvSelector(true)
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-start gap-3 border-b border-border p-4">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-foreground" title={jobName(job)}>{jobName(job)}</p>
          <div className="mt-1.5"><StatusBadge status={job.status} /></div>
        </div>
        <button onClick={onClose} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="Close">
          <X size={15} />
        </button>
      </div>

      {/* Actions bar */}
      <div className="flex flex-wrap items-center gap-1 border-b border-border px-3 py-2">
        {(cap.canCopySingle || cap.canCopyAll) && (
          <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(allLinks.join('\n')).catch(() => undefined)}>
            <Copy size={13} />{allLinks.length > 1 ? 'Copy all' : 'Copy link'}
          </Button>
        )}
        {cap.canUnrestrict && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('unrestrict', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Unlock size={13} />}
            {allLinks.length > 0 ? 'Unlock again' : 'Unlock'}
          </Button>
        )}
        {cap.canRefresh && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('refresh', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />} Refresh
          </Button>
        )}
        {cap.canSelectFiles && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('select_files', job.id)}>
            Select all files
          </Button>
        )}
        {(cap.canSendDirect || cap.canChooseSendDest) && (
          <Button variant="outline" size="sm" disabled={busy} onClick={handleSendDirect}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />} Send
          </Button>
        )}
        {cap.canResend && (
          <Button variant="outline" size="sm" disabled={busy} onClick={handleResend}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />} Resend
          </Button>
        )}
        {cap.canSendOtherDest && (
          <Button variant="outline" size="sm" disabled={busy} onClick={handleSendOther}>
            <Send size={13} /> Other dest
          </Button>
        )}
        {cap.canStart && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('start', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} Start
          </Button>
        )}
        {cap.canRestart && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onAction('restart', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <RefreshCcw size={13} />} Restart
          </Button>
        )}
        {cap.canCloneWithProvider && (
          <Button variant="outline" size="sm" disabled={busy} onClick={handleClone}>
            <Copy size={13} /> Clone
          </Button>
        )}
        {cap.canCancel && (
          <Button variant="outline" size="sm" disabled={busy}
            className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
            onClick={() => onAction('cancel', job.id)}>
            {busy ? <Loader2 size={13} className="animate-spin" /> : <CircleX size={13} />} Cancel
          </Button>
        )}
        {cap.canCancelLocalDownload && (
          <Button variant="outline" size="sm" disabled={busy}
            className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
            onClick={() => onAction('cancel_local_download', job.id)}>
            <CircleX size={13} /> Stop download
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
        <div className="flex items-start gap-2 border-b border-border bg-red-50 px-4 py-2 text-xs text-red-700 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={13} className="mt-0.5 shrink-0" />
          <span><span className="font-medium">Action failed:</span> {actionError}</span>
        </div>
      )}

      {/* Inline selectors — mutually exclusive */}
      {showDestSelector && (
        <div className="border-b border-border p-3">
          <InlineSelector<RealJobDestinationConfig>
            title={showDestSelector === 'other' ? 'Select another destination' : 'Select destination'}
            items={showDestSelector === 'other'
              ? cap.activeDestinations.filter(d => d.id !== job.destination_config_id)
              : cap.activeDestinations}
            labelFn={destLabel}
            onSelect={async (d) => { setShowDestSelector(null); setTab('destination'); await onAction('send_to_destination', job.id, { destination_config_id: d.id }) }}
            onCancel={() => setShowDestSelector(null)}
          />
        </div>
      )}
      {showProvSelector && (
        <div className="border-b border-border p-3">
          <InlineSelector<RealJobProviderConfig>
            title="Select provider to clone with"
            items={cap.otherProviders}
            labelFn={provLabel}
            onSelect={async (p) => { setShowProvSelector(false); await onAction('clone_with_provider', job.id, { provider_config_id: p.id }) }}
            onCancel={() => setShowProvSelector(false)}
          />
        </div>
      )}

      {/* Tabs */}
      <nav className="flex shrink-0 overflow-x-auto border-b border-border">
        {TABS.map(({ id, label }) => (
          <button key={id} onClick={() => setTab(id)}
            className={cn('shrink-0 px-3.5 py-2.5 text-xs transition-colors', tab === id ? 'border-b-2 border-primary font-medium text-primary' : 'text-muted-foreground hover:text-foreground')}
            aria-selected={tab === id}>{label}</button>
        ))}
      </nav>

      {/* Tab content */}
      <div className="min-h-0 flex-1 overflow-y-auto">

        {/* ── Summary ────────────────────────────────────────────── */}
        {tab === 'summary' && (
          <div className="space-y-3 p-4 text-xs">
            {/* Hint: file selection required */}
            {job.status === 'waiting_files_selection' && (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
                <p>File selection required. Click <span className="font-medium">Select all files</span> in the action bar to proceed automatically, or open the <span className="font-medium">Files</span> tab to review available files.</p>
              </div>
            )}

            <Row label="Source type" value={job.source_type} />
            <Row label="Provider"    value={jobProvider(job)} />
            <Row label="Destination" value={jobDestination(job) ?? 'Links only'} />
            <Row label="Files"       value={job.files.length || null} />
            <Row label="Size"        value={formatBytes(job.filesize)} />

            {/* Provider download progress — hide for statuses where progress has no meaning */}
            {!['created', 'failed', 'cancelled', 'links_only'].includes(job.status) && (
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-muted-foreground">Download progress</span>
                  <span className="font-medium text-foreground">{job.progress ?? 0}%</span>
                </div>
                <ProgressBar percent={job.progress ?? 0} />
                {job.provider_status && (
                  <p className="mt-1 text-[11px] text-muted-foreground">Provider: {job.provider_status}</p>
                )}
              </div>
            )}

            {/* Last job error — shown before timestamps so it is not buried */}
            {job.error_message && (
              <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
                <p className="mb-1 font-medium">Last job error</p>
                <p className="font-mono text-[11px]">{job.error_message}</p>
              </div>
            )}

            <Row label="Created"   value={job.created_at ? new Date(job.created_at).toLocaleString() : null} />
            <Row label="Updated"   value={job.updated_at ? new Date(job.updated_at).toLocaleString() : null} />
            <Row label="Cancelled" value={job.cancelled_at ? new Date(job.cancelled_at).toLocaleString() : null} />

            {/* Links ready card — shown whenever download links exist */}
            {showLinksHint && (
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-3 py-2">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <LinkIcon size={12} className="shrink-0" />
                  <span>Download links are ready.</span>
                </div>
                <Button variant="outline" size="sm" className="h-6 shrink-0 px-2 text-xs" onClick={() => setTab('links')}>
                  Open Links
                </Button>
              </div>
            )}
          </div>
        )}

        {/* ── Destination ────────────────────────────────────────── */}
        {tab === 'destination' && (
          <div className="space-y-3 p-4 text-xs">
            {!cap.hasAnyDestination && !job.send_to_destination && (
              <p className="italic text-muted-foreground">No destination configured for this job.</p>
            )}
            <Row label="Send configured" value={job.send_to_destination ? 'Yes' : 'No'} />
            <Row label="Sent"            value={job.sent_to_destination ? 'Yes' : 'No'} />
            <Row label="Status"          value={job.destination_status} />

            {/* Destination download progress bar */}
            {job.destination_progress > 0 && (
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-muted-foreground">Destination progress</span>
                  <span className="font-medium text-foreground">{job.destination_progress}%</span>
                </div>
                <ProgressBar
                  percent={job.destination_progress}
                  colorClass={job.destination_status === 'sent' ? 'bg-emerald-500' : job.destination_status === 'failed' ? 'bg-red-500' : 'bg-primary'}
                />
              </div>
            )}

            <Row label="Message"      value={job.destination_message} />
            <Row label="Path"         value={job.destination_display_path ?? job.destination_path} />
            <Row label="Last attempt" value={job.destination_last_attempt ? new Date(job.destination_last_attempt).toLocaleString() : null} />
            <Row label="Sent at"      value={job.sent_to_destination_at ? new Date(job.sent_to_destination_at).toLocaleString() : null} />
          </div>
        )}

        {/* ── Files ─────────────────────────────────────────────── */}
        {tab === 'files' && (
          <JobFilesTable
            files={job.files}
            onUnrestrictFile={
              job.output_mode === 'per_file' &&
              ['downloaded', 'ready', 'completed', 'partially_ready'].includes(job.status)
                ? (fid) => onAction('unrestrict_file', job.id, { file_id: fid })
                : undefined
            }
          />
        )}

        {/* ── Links ─────────────────────────────────────────────── */}
        {tab === 'links' && (
          <div className="p-4">
            {allLinks.length === 0
              ? <p className="text-sm text-muted-foreground">No download links available yet.</p>
              : (
                <>
                  {allLinks.length > 1 && (
                    <div className="mb-3 flex justify-end">
                      <Button variant="outline" size="sm"
                        onClick={() => navigator.clipboard.writeText(allLinks.join('\n')).catch(() => undefined)}>
                        <Copy size={13} /> Copy all {allLinks.length} links
                      </Button>
                    </div>
                  )}
                  <ul className="flex flex-col gap-2">
                    {job.output_mode === 'per_file'
                      ? job.output_links.filter(l => !!l.url).map((l, i) => {
                          const url = l.url as string
                          const canReunlock = !!l.file_id &&
                            ['downloaded', 'ready', 'completed', 'partially_ready'].includes(job.status)
                          return (
                            <li key={i} className="flex items-center gap-2 rounded-md border border-border bg-muted/20 px-3 py-2">
                              <LinkIcon size={11} className="shrink-0 text-muted-foreground" />
                              <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">{url}</span>
                              {canReunlock && (
                                <button
                                  disabled={busy}
                                  onClick={() => onAction('unrestrict_file', job.id, { file_id: l.file_id })}
                                  className="shrink-0 text-xs text-muted-foreground hover:text-primary disabled:opacity-50"
                                  title="Regenerate link"
                                >
                                  Unlock again
                                </button>
                              )}
                              <CopyBtn text={url} label={`Copy link ${i + 1}`} small />
                            </li>
                          )
                        })
                      : allLinks.map((url, i) => (
                          <li key={i} className="flex items-center gap-2 rounded-md border border-border bg-muted/20 px-3 py-2">
                            <LinkIcon size={11} className="shrink-0 text-muted-foreground" />
                            <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">{url}</span>
                            <CopyBtn text={url} label={`Copy link ${i + 1}`} small />
                          </li>
                        ))
                    }
                  </ul>
                </>
              )}
          </div>
        )}

        {/* ── Technical ─────────────────────────────────────────── */}
        {tab === 'technical' && (
          <div className="space-y-2.5 p-4 text-xs">
            <Row label="Job ID"             value={<span className="font-mono text-[11px]">{job.id}</span>} />
            <Row label="Source type"        value={job.source_type} />
            <Row label="Output mode"        value={job.output_mode} />
            <Row label="Provider resource"  value={job.provider_resource_id ? <span className="font-mono text-[11px]">{job.provider_resource_id}</span> : null} />
            <Row label="Provider status"    value={job.provider_status} />
            <Row label="Created"            value={job.created_at ? new Date(job.created_at).toLocaleString() : null} />
            <Row label="Updated"            value={job.updated_at ? new Date(job.updated_at).toLocaleString() : null} />
            <Row label="Started"            value={job.started_at ? new Date(job.started_at).toLocaleString() : null} />
            <Row label="Completed"          value={job.completed_at ? new Date(job.completed_at).toLocaleString() : null} />
            <Row label="Cancelled"          value={job.cancelled_at ? new Date(job.cancelled_at).toLocaleString() : null} />
          </div>
        )}
      </div>

      {/* Sticky provider progress — only for active downloads */}
      {stickyProgress && <JobProgressCard progress={stickyProgress} />}
    </div>
  )
}
