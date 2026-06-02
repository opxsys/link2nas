import { useState, useEffect, useCallback } from 'react'
import { Loader2, AlertCircle, BookOpen, CheckSquare } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import {
  listUserAnnouncements,
  markAnnouncementRead,
  acknowledgeAnnouncement,
} from '@/api/announcements'
import { ApiError } from '@/api/client'
import type { UserAnnouncement } from '@/api/announcements'

const TYPE_CLASS: Record<string, string> = {
  news:        'border-border bg-muted text-muted-foreground',
  maintenance: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400',
  incident:    'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  security:    'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400',
}
const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize'

export default function AnnouncementsUserView() {
  const [items, setItems] = useState<UserAnnouncement[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [acting, setActing] = useState<Set<string>>(new Set())

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setItems(await listUserAnnouncements())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load announcements.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function startActing(id: string) {
    setActing(prev => { const s = new Set(prev); s.add(id); return s })
  }
  function stopActing(id: string) {
    setActing(prev => { const s = new Set(prev); s.delete(id); return s })
  }

  async function handleRead(id: string) {
    startActing(id)
    try {
      await markAnnouncementRead(id)
      setItems(prev => prev.map(a => a.id === id ? { ...a, read_at: new Date().toISOString() } : a))
    } finally {
      stopActing(id)
    }
  }

  async function handleAcknowledge(id: string) {
    startActing(id)
    try {
      await acknowledgeAnnouncement(id)
      setItems(prev => prev.map(a => a.id === id ? { ...a, acknowledged_at: new Date().toISOString() } : a))
    } finally {
      stopActing(id)
    }
  }

  return (
    <SectionCard title="Announcements" description="Messages from administrators.">
      {loading && (
        <div className="flex items-center gap-2 py-6 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading…</span>
        </div>
      )}
      {!loading && error && (
        <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          {error}
        </div>
      )}
      {!loading && !error && items.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground">No announcements.</p>
      )}
      {!loading && !error && items.length > 0 && (
        <ul className="divide-y divide-border">
          {items.map((ann) => {
            const busy = acting.has(ann.id)
            return (
              <li key={ann.id} className={`py-3 ${ann.read_at ? 'opacity-70' : ''}`}>
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{ann.title}</span>
                  <span className={`${BADGE} ${TYPE_CLASS[ann.type] ?? TYPE_CLASS.news}`}>{ann.type}</span>
                  {ann.read_at && (
                    <span className="text-xs text-muted-foreground">Read</span>
                  )}
                  {ann.acknowledged_at && (
                    <span className="text-xs text-muted-foreground">Acknowledged</span>
                  )}
                </div>
                <p className="mb-2 line-clamp-2 text-xs text-muted-foreground">{ann.body}</p>
                <div className="flex flex-wrap gap-2">
                  {!ann.read_at && (
                    <Button variant="outline" size="sm" className="h-7 text-xs" disabled={busy}
                      onClick={() => handleRead(ann.id)}>
                      {busy ? <Loader2 size={11} className="animate-spin" aria-hidden="true" /> : <BookOpen size={11} aria-hidden="true" />}
                      Mark as read
                    </Button>
                  )}
                  {ann.require_acknowledgement && !ann.acknowledged_at && (
                    <Button variant="outline" size="sm" className="h-7 text-xs" disabled={busy}
                      onClick={() => handleAcknowledge(ann.id)}>
                      {busy ? <Loader2 size={11} className="animate-spin" aria-hidden="true" /> : <CheckSquare size={11} aria-hidden="true" />}
                      Acknowledge
                    </Button>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </SectionCard>
  )
}
