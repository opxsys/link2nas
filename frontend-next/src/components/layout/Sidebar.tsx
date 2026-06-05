import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip'
import { NAV_ITEMS } from '@/lib/nav'
import SidebarNavItem from './SidebarNavItem'
import { useIntegrationSettings, isProwlarrAvailable, resolveHomePath } from '@/lib/useIntegrationSettings'
import { useAnnouncementBadge } from '@/context/AnnouncementBadgeContext'
import { useMe } from '@/lib/useMe'
import { useAppInfo } from '@/lib/useAppInfo'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { settings: integrationSettings } = useIntegrationSettings()
  const { count: announcementCount } = useAnnouncementBadge()
  const navigate = useNavigate()
  const { me } = useMe()
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'
  const isSuperAdmin = me?.role === 'super_admin'

  const visibleItems = NAV_ITEMS.filter((item) => {
    if (item.to === '/prowlarr' && !isProwlarrAvailable(integrationSettings)) return false
    if (item.superAdminOnly && !isSuperAdmin) return false
    return true
  })

  const displayName = me?.display_name || me?.email || 'admin'
  const roleLabel   = me?.role === 'super_admin' ? 'Super Admin'
                    : me?.role === 'user'         ? 'User'
                    : me?.role                   ?? 'Administrator'
  const initials    = displayName.charAt(0).toUpperCase()

  return (
    <TooltipProvider delayDuration={150}>
      <aside
        style={{ width: collapsed ? 56 : 240 }}
        className="hidden md:flex flex-shrink-0 flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200 ease-in-out overflow-hidden"
      >
        {/* Brand */}
        <div
          className={cn(
            'flex h-14 shrink-0 items-center border-b border-sidebar-border',
            collapsed ? 'justify-center' : 'px-4',
          )}
        >
          {!collapsed && (
            <button
              onClick={() => navigate(resolveHomePath(integrationSettings))}
              className="flex-1 truncate text-left text-sm font-semibold tracking-wide text-sidebar-foreground transition-opacity hover:opacity-70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded"
              aria-label="Go to home page"
            >
              {appName}
            </button>
          )}
          <button
            onClick={onToggle}
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3">
          <ul className={cn('space-y-0.5', collapsed ? 'px-1.5' : 'px-2')}>
            {visibleItems.map((item) => (
              <li key={item.to}>
                <SidebarNavItem
                  item={item}
                  collapsed={collapsed}
                  badge={item.to === '/announcements' ? announcementCount : undefined}
                />
              </li>
            ))}
          </ul>
        </nav>

        {/* User block — informational, click goes to Account settings */}
        <div className="shrink-0 border-t border-sidebar-border">
          {collapsed ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => navigate('/settings')}
                  className="flex w-full items-center justify-center p-3 transition-colors hover:bg-accent/50"
                  aria-label="Go to account settings"
                >
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary select-none">
                    {initials}
                  </div>
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">{displayName}</TooltipContent>
            </Tooltip>
          ) : (
            <button
              onClick={() => navigate('/settings')}
              className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/50"
              aria-label="Go to account settings"
            >
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary select-none">
                {initials}
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-sidebar-foreground">{displayName}</p>
                <p className="truncate text-xs text-muted-foreground">{roleLabel}</p>
              </div>
            </button>
          )}
        </div>
      </aside>
    </TooltipProvider>
  )
}
