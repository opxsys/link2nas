import { useState, useEffect, useCallback, useRef } from 'react'
import { Loader2, AlertCircle, Pencil, Trash2, BarChart2, Plus, CheckSquare, Mail, CheckCircle2, XCircle, X, AlertTriangle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n'
import {
  listAnnouncements, deleteAnnouncement,
  getAnnouncementSystemSettings, saveAnnouncementSystemSettings,
} from '@/api/admin-announcements'
import type { RealAnnouncement } from './admin.types'
import AdminAnnouncementForm from './AdminAnnouncementForm'
import AdminAnnouncementTracking from './AdminAnnouncementTracking'
import { emitAnnouncementsChanged } from '@/lib/announcementEvents'
import { invalidateMe } from '@/lib/useMe'

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
  const { t } = useI18n()
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
            {ann.is_active ? t('badgeActive') : t('adminAnnInactive')}
          </span>
          {ann.require_acknowledgement && (
            <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">
              <CheckSquare size={10} aria-hidden="true" /> {t('adminAnnRequiresAck')}
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
              {deleting ? <Loader2 size={11} className="animate-spin" aria-hidden="true" /> : t('confirm')}
            </Button>
            <Button size="sm" variant="outline" className="h-7 text-xs" disabled={deleting} onClick={onDeleteCancel}>{t('cancel')}</Button>
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
  const { t } = useI18n()
  const [systemEnabled, setSystemEnabled] = useState<boolean | null>(null)
  const [savingToggle, setSavingToggle] = useState(false)

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

  useEffect(() => {
    getAnnouncementSystemSettings()
      .then((s) => setSystemEnabled(s.enabled))
      .catch(() => setSystemEnabled(true))
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setItems(await listAnnouncements())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('adminLoadAnnouncements'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleToggleSystem() {
    if (systemEnabled === null || savingToggle) return
    const next = !systemEnabled
    setSavingToggle(true)
    try {
      const result = await saveAnnouncementSystemSettings({ enabled: next })
      setSystemEnabled(result.enabled)
      invalidateMe()
      emitAnnouncementsChanged()
    } catch { /* non-critical — keep current state */ }
    finally { setSavingToggle(false) }
  }

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
      setBanner(t('adminAnnDeleted'))
      successTimer.current = setTimeout(() => setBanner(null), 4000)
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : t('deleteFailed'))
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

  // Form and tracking only accessible when system is enabled
  if (view === 'form' && systemEnabled !== false) {
    return <AdminAnnouncementForm ann={editingAnn} onSave={handleFormSave} onCancel={() => setView('list')} />
  }
  if (view === 'tracking' && trackingId && systemEnabled !== false) {
    return <AdminAnnouncementTracking id={trackingId} onBack={() => setView('list')} />
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Global system toggle */}
      <SectionCard
        title={t('adminAnnSystemTitle')}
        description={t('adminAnnSystemDesc')}
      >
        <div className="flex items-center gap-3">
          <button
            role="switch"
            aria-checked={systemEnabled ?? false}
            onClick={handleToggleSystem}
            disabled={systemEnabled === null || savingToggle}
            aria-label={t('adminToggleAnnouncementsSystem')}
            className={cn(
              'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              'disabled:cursor-not-allowed disabled:opacity-50',
              systemEnabled ? 'bg-primary' : 'bg-input',
            )}
          >
            <span
              className={cn(
                'pointer-events-none inline-block h-4 w-4 rounded-full bg-background shadow-lg transition-transform',
                systemEnabled ? 'translate-x-4' : 'translate-x-0',
              )}
            />
          </button>
          <span className="text-sm font-medium text-foreground">
            {systemEnabled === null
              ? <Loader2 size={13} className="inline animate-spin" aria-hidden="true" />
              : systemEnabled ? t('badgeActive') : t('badgeDisabled')}
          </span>
        </div>
      </SectionCard>

      {/* Disabled warning */}
      {systemEnabled === false && (
        <div className="flex items-start gap-3 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
          <AlertTriangle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <p>
            {t('adminAnnSystemDisabledWarn')}
          </p>
        </div>
      )}

      {/* List — only when enabled */}
      {systemEnabled === true && (
        <SectionCard
          title={t('adminAnnListTitle')}
          description={t('adminAnnListDesc')}
          actions={
            <Button size="sm" variant="outline" onClick={() => { setEditingAnn(null); setView('form') }}>
              <Plus size={13} className="mr-1.5" aria-hidden="true" /> {t('adminNewAnnouncement')}
            </Button>
          }
        >
          {loading && (
            <div className="flex items-center gap-2 py-6 text-muted-foreground">
              <Loader2 size={18} className="animate-spin" aria-hidden="true" />
              <span className="text-sm">{t('loading')}</span>
            </div>
          )}
          {banner && (
            <div className="mb-2 flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
              <CheckCircle2 size={15} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{banner}</span>
              <button
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                onClick={() => { if (successTimer.current) clearTimeout(successTimer.current); setBanner(null) }}
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
          {fetchError && (
            <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
              <div>
                <p className="font-medium">{t('adminLoadAnnouncements')}</p>
                <p className="mt-0.5 text-xs">{fetchError}</p>
                <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
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
                aria-label={t('dismiss')}
              >
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
          {!loading && !fetchError && items.length === 0 && (
            <p className="py-4 text-sm text-muted-foreground">{t('adminNoAnnouncements')}</p>
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
      )}
    </div>
  )
}
