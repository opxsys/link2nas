import { useState, useEffect, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { useMe } from '@/lib/useMe'
import { AlertCircle, AlertTriangle, Info, X, BookOpen, CheckSquare, Loader2 } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  listActiveAnnouncements,
  markAnnouncementRead,
  acknowledgeAnnouncement,
} from '@/api/announcements'
import type { UserAnnouncement } from '@/api/announcements'
import { subscribeAnnouncementsChanged, emitAnnouncementsChanged } from '@/lib/announcementEvents'

// ── Severity display config ────────────────────────────────────────────────

interface SevStyle {
  wrapper: string
  text: string
  muted: string
  label: string
  Icon: LucideIcon
}

const SEV: Record<string, SevStyle> = {
  critical: {
    wrapper: 'bg-red-50 border-red-200 dark:bg-red-950 dark:border-red-800',
    text:    'text-red-900 dark:text-red-100',
    muted:   'text-red-700 dark:text-red-300',
    label:   'Critical',
    Icon:    AlertCircle,
  },
  warning: {
    wrapper: 'bg-amber-50 border-amber-200 dark:bg-amber-950 dark:border-amber-800',
    text:    'text-amber-900 dark:text-amber-100',
    muted:   'text-amber-700 dark:text-amber-300',
    label:   'Warning',
    Icon:    AlertTriangle,
  },
  info: {
    wrapper: 'bg-blue-50 border-blue-200 dark:bg-blue-950 dark:border-blue-800',
    text:    'text-blue-900 dark:text-blue-100',
    muted:   'text-blue-700 dark:text-blue-300',
    label:   'Info',
    Icon:    Info,
  },
}

// ── Banner selection (mirrors legacy pickBannerAnnouncement) ───────────────

const SEVERITY_RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 }

function pickBanner(items: UserAnnouncement[], dismissed: Set<string>): UserAnnouncement | null {
  const candidates = items.filter((a) => {
    if (!a.show_as_banner) return false
    if (dismissed.has(a.id)) return false
    if (a.require_acknowledgement) return !a.user_status.acknowledged_at
    return !a.user_status.read_at
  })
  if (!candidates.length) return null
  return [...candidates].sort((a, b) => {
    const ra = SEVERITY_RANK[a.severity] ?? 3
    const rb = SEVERITY_RANK[b.severity] ?? 3
    if (ra !== rb) return ra - rb
    return (b.created_at || '').localeCompare(a.created_at || '')
  })[0]
}

// ── Component ──────────────────────────────────────────────────────────────

export default function AnnouncementBanner() {
  const { pathname } = useLocation()
  const { me } = useMe()
  const [items, setItems] = useState<UserAnnouncement[]>([])
  const [dismissed, setDismissed] = useState<Set<string>>(new Set())
  const [acting, setActing] = useState(false)

  const refresh = useCallback(() => {
    if (me?.announcements_enabled === false) { setItems([]); return }
    listActiveAnnouncements().then(setItems).catch(() => {})
  }, [me?.announcements_enabled])

  // Refetch on every navigation (AppShell never unmounts during SPA routing)
  useEffect(() => { refresh() }, [pathname, refresh])

  // Refetch when admin creates/edits/deletes or user reads/acknowledges elsewhere
  useEffect(() => subscribeAnnouncementsChanged(refresh), [refresh])

  const _banner = pickBanner(items, dismissed)
  if (!_banner) return null
  // Capture non-null type explicitly so async closures below are correctly typed.
  const banner: UserAnnouncement = _banner

  const style = SEV[banner.severity] ?? SEV.info
  const { Icon } = style
  const needsAck = banner.require_acknowledgement && !banner.user_status.acknowledged_at
  const needsRead = !banner.user_status.read_at

  function dismiss() {
    setDismissed((prev) => new Set([...prev, banner.id]))
  }

  async function handleRead() {
    if (acting) return
    setActing(true)
    try {
      await markAnnouncementRead(banner.id)
      const now = new Date().toISOString()
      setItems((prev) =>
        prev.map((a) =>
          a.id === banner.id
            ? { ...a, user_status: { ...a.user_status, read_at: now } }
            : a,
        ),
      )
      emitAnnouncementsChanged()
    } catch { /* non-critical — banner stays visible */ }
    finally { setActing(false) }
  }

  async function handleAcknowledge() {
    if (acting) return
    setActing(true)
    try {
      await acknowledgeAnnouncement(banner.id)
      const now = new Date().toISOString()
      setItems((prev) =>
        prev.map((a) =>
          a.id === banner.id
            ? {
                ...a,
                user_status: {
                  ...a.user_status,
                  read_at: a.user_status.read_at ?? now,
                  acknowledged_at: now,
                },
              }
            : a,
        ),
      )
      emitAnnouncementsChanged()
    } catch { /* non-critical */ }
    finally { setActing(false) }
  }

  const btnClass =
    `inline-flex items-center gap-1 rounded border border-current/25 px-2 py-1 text-xs ` +
    `transition-colors hover:bg-current/10 focus-visible:outline-none focus-visible:ring-2 ` +
    `focus-visible:ring-current/40 disabled:cursor-not-allowed disabled:opacity-50 ${style.muted}`

  return (
    <div
      role="region"
      aria-label="Announcement banner"
      className={`shrink-0 border-b ${style.wrapper}`}
    >
      <div className="flex items-start gap-3 px-4 py-2.5">
        <Icon size={15} className={`mt-0.5 shrink-0 ${style.muted}`} aria-hidden="true" />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className={`text-[10px] font-semibold uppercase tracking-widest ${style.muted}`}>
              {style.label}
            </span>
            <span className={`text-sm font-medium break-words ${style.text}`}>
              {banner.title}
            </span>
          </div>
          {banner.body && (
            <p className={`mt-0.5 line-clamp-2 break-words text-xs ${style.muted}`}>
              {banner.body}
            </p>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {needsAck && (
            <button
              className={btnClass}
              onClick={handleAcknowledge}
              disabled={acting}
              aria-label={`Acknowledge: ${banner.title}`}
            >
              {acting
                ? <Loader2 size={11} className="animate-spin" aria-hidden="true" />
                : <CheckSquare size={11} aria-hidden="true" />}
              Acknowledge
            </button>
          )}
          {!needsAck && needsRead && (
            <button
              className={btnClass}
              onClick={handleRead}
              disabled={acting}
              aria-label={`Mark as read: ${banner.title}`}
            >
              {acting
                ? <Loader2 size={11} className="animate-spin" aria-hidden="true" />
                : <BookOpen size={11} aria-hidden="true" />}
              <span className="hidden sm:inline">Mark read</span>
            </button>
          )}
          <button
            className={`rounded p-1.5 transition-colors hover:bg-current/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-current/40 ${style.muted}`}
            onClick={dismiss}
            aria-label={`Dismiss announcement: ${banner.title}`}
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  )
}
