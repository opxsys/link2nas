import { useState, useEffect, useCallback, useRef } from 'react'
import { Loader2, AlertCircle, Pencil, Trash2, BarChart2, Plus, CheckSquare, Mail, CheckCircle2, XCircle, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listAnnouncements, deleteAnnouncement } from '@/api/admin-announcements'
import type { RealAnnouncement } from './admin.types'
import AdminAnnouncementForm from './AdminAnnouncementForm'
import AdminAnnouncementTracking from './AdminAnnouncementTracking'
import { emitAnnouncementsChanged } from '@/lib/announcementEvents'

type View = 'list' | 'form' | 'tracking'

const TYPE_CLASS: Record<string, string> = {
  news:        'border-border bg-muted text-muted-foreground',
  maintenance: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400',
  incident:    'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  security:    'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400',
}
const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize'

function AnnRow({
  ann, pendingDeleteId, deleting,
  onEdit, onTrack, onDeleteAsk, onDeleteConfirm, onDeleteCancel,
}: {
  ann: RealAnnouncement
  pendingDeleteId: string | null
  deleting: boolean
  onEdit: () => void
  onTrack: () => void
  onDeleteAsk: () => void
  onDeleteConfirm: () => void
  onDeleteCancel: () => void
}) {
  const isPending = pendingDeleteId === ann.id
  return (
    <li className="flex items-start justify-between gap-4 border-b border-border py-3 last:border-0">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{ann.title}</span>
          <span className={`${BADGE} ${TYPE_CLASS[ann.type] ?? TYPE_CLASS.news}`}>{ann.type}</span>
          <span className={`${BADGE} ${ann.is_active
            ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400'
            : 'border-border bg-muted text-muted-foreground'}`}>
            {ann.is_active ? 'Active' : 'Inactive'}
          </span>
          {ann.require_acknowledgement && (
            <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">
              <CheckSquare size={10} aria-hidden="true" /> Requires ack
            </span>
          )}
          {ann.send_email && (
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <Mail size={10} aria-hidden="true" /> Email
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Created {new Date(ann.created_at).toLocaleDateString()}
          {ann.starts_at && ` · Starts ${new Date(ann.starts_at).toLocaleString()}`}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {isPending ? (
          <>
            <Button size="sm" variant="destructive" className="h-7 text-xs" disabled={deleting} onClick={onDeleteConfirm}>
              {deleting ? <Loader2 size={11} className="animate-spin" aria-hidden="true" /> : 'Confirm'}
            </Button>
            <Button size="sm" variant="outline" className="h-7 text-xs" disabled={deleting} onClick={onDeleteCancel}>Cancel</Button>
          </>
        ) : (
          <>
            <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit ${ann.title}`} onClick={onEdit}><Pencil size={13} /></Button>
            <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Tracking ${ann.title}`} onClick={onTrack}><BarChart2 size={13} /></Button>
            <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" aria-label={`Delete ${ann.title}`} onClick={onDeleteAsk}><Trash2 size={13} /></Button>
          </>
        )}
      </div>
    </li>
  )
}

interface Props {
  openCreate?: boolean
}

export default function AdminAnnouncements({ openCreate }: Props) {
  const [items, setItems] = useState<RealAnnouncement[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [view, setView] = useState<View>(openCreate ? 'form' : 'list')
  const [editingAnn, setEditingAnn] = useState<RealAnnouncement | null>(null)
  const [trackingId, setTrackingId] = useState<string | null>(null)
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [banner, setBanner] = useState<string | null>(null)
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setItems(await listAnnouncements())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load announcements.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleDeleteConfirm() {
    if (!pendingDeleteId) return
    setDeleting(true)
    setDeleteError(null)
    try {
      await deleteAnnouncement(pendingDeleteId)
      setItems((prev) => prev.filter((a) => a.id !== pendingDeleteId))
      setPendingDeleteId(null)
      emitAnnouncementsChanged()
      if (successTimer.current) clearTimeout(successTimer.current)
      setBanner('Announcement deleted.')
      successTimer.current = setTimeout(() => setBanner(null), 4000)
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Delete failed.')
    } finally {
      setDeleting(false)
    }
  }

  function handleFormSave(saved: RealAnnouncement) {
    const wasEdit = editingAnn !== null
    setItems((prev) => {
      const idx = prev.findIndex((a) => a.id === saved.id)
      return idx >= 0 ? prev.map((a) => (a.id === saved.id ? saved : a)) : [saved, ...prev]
    })
    setEditingAnn(null)
    setView('list')
    emitAnnouncementsChanged()
    if (successTimer.current) clearTimeout(successTimer.current)
    setBanner(wasEdit ? `"${saved.title}" updated.` : `"${saved.title}" created.`)
    successTimer.current = setTimeout(() => setBanner(null), 4000)
  }

  if (view === 'form') {
    return <AdminAnnouncementForm ann={editingAnn} onSave={handleFormSave} onCancel={() => setView('list')} />
  }

  if (view === 'tracking' && trackingId) {
    return <AdminAnnouncementTracking id={trackingId} onBack={() => setView('list')} />
  }

  return (
    <SectionCard
      title="Announcements"
      description="Broadcast messages to users."
      actions={
        <Button size="sm" variant="outline" onClick={() => { setEditingAnn(null); setView('form') }}>
          <Plus size={13} className="mr-1.5" aria-hidden="true" /> New announcement
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading…</span>
        </div>
      )}
      {banner && (
        <div className="mb-2 flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
          <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
          <span className="flex-1">{banner}</span>
          <button
            className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => { if (successTimer.current) clearTimeout(successTimer.current); setBanner(null) }}
            aria-label="Dismiss"
          >
            <X size={13} aria-hidden="true" />
          </button>
        </div>
      )}
      {fetchError && (
        <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <p className="font-medium">Failed to load announcements</p>
            <p className="mt-0.5 text-xs">{fetchError}</p>
            <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
          </div>
        </div>
      )}
      {deleteError && (
        <div className="mb-2 flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <XCircle size={15} className="shrink-0" aria-hidden="true" />
          <span className="flex-1">{deleteError}</span>
          <button
            className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => setDeleteError(null)}
            aria-label="Dismiss"
          >
            <X size={13} aria-hidden="true" />
          </button>
        </div>
      )}
      {!loading && !fetchError && items.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground">No announcements yet.</p>
      )}
      {items.length > 0 && (
        <ul>
          {items.map((ann) => (
            <AnnRow
              key={ann.id}
              ann={ann}
              pendingDeleteId={pendingDeleteId}
              deleting={deleting}
              onEdit={() => { setEditingAnn(ann); setView('form') }}
              onTrack={() => { setTrackingId(ann.id); setView('tracking') }}
              onDeleteAsk={() => { setPendingDeleteId(ann.id); setDeleteError(null) }}
              onDeleteConfirm={handleDeleteConfirm}
              onDeleteCancel={() => setPendingDeleteId(null)}
            />
          ))}
        </ul>
      )}
    </SectionCard>
  )
}
