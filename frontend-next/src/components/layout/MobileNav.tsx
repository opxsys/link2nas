import { useEffect } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { NAV_ITEMS } from '@/lib/nav'
import { useIntegrationSettings, isProwlarrAvailable, resolveHomePath } from '@/lib/useIntegrationSettings'
import { useAnnouncementBadge } from '@/context/AnnouncementBadgeContext'
import { useAppInfo } from '@/lib/useAppInfo'
import { useMe } from '@/lib/useMe'

interface Props {
  open: boolean
  onClose: () => void
}

export default function MobileNav({ open, onClose }: Props) {
  const { settings: integrationSettings } = useIntegrationSettings()
  const { count: announcementCount } = useAnnouncementBadge()
  const location = useLocation()
  const navigate = useNavigate()
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'
  const { me } = useMe()
  const isSuperAdmin = me?.role === 'super_admin'

  const visibleItems = NAV_ITEMS.filter((item) => {
    if (item.to === '/prowlarr' && !isProwlarrAvailable(integrationSettings)) return false
    if (item.superAdminOnly && !isSuperAdmin) return false
    return true
  })

  // Close on ESC
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  // Close when route changes (programmatic navigation)
  useEffect(() => {
    if (open) onClose()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname])

  // Prevent body scroll while open
  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : ''
    return () => { document.body.style.overflow = '' }
  }, [open])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 md:hidden" aria-modal="true" role="dialog" aria-label="Navigation">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-sidebar-border bg-sidebar">
        {/* Brand + close */}
        <div className="flex h-14 shrink-0 items-center justify-between border-b border-sidebar-border px-4">
          <button
            onClick={() => { navigate(resolveHomePath(integrationSettings)); onClose() }}
            className="text-sm font-semibold tracking-wide text-sidebar-foreground transition-opacity hover:opacity-70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded"
            aria-label="Go to home page"
          >
            {appName}
          </button>
          <button
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Close navigation"
          >
            <X size={15} aria-hidden="true" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3">
          <ul className="space-y-0.5 px-2">
            {visibleItems.map(({ to, label, icon: Icon, end }) => {
              const badge = to === '/announcements' ? announcementCount : 0
              return (
                <li key={to}>
                  <NavLink
                    to={to}
                    end={end}
                    onClick={onClose}
                    className={({ isActive }) =>
                      cn(
                        'flex h-9 items-center gap-3 rounded-md px-3 text-sm text-muted-foreground transition-colors',
                        'hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                        isActive && 'bg-primary/10 text-primary font-medium',
                      )
                    }
                  >
                    <Icon size={18} aria-hidden="true" className="shrink-0" />
                    <span className="truncate">{label}</span>
                    {badge > 0 && (
                      <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-semibold leading-none text-primary-foreground">
                        {badge > 99 ? '99+' : badge}
                      </span>
                    )}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </nav>
      </aside>
    </div>
  )
}
