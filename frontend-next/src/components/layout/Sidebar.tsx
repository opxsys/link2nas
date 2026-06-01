import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip'
import { NAV_ITEMS } from '@/lib/nav'
import SidebarNavItem from './SidebarNavItem'
import { useIntegrationSettings, isProwlarrAvailable } from '@/lib/useIntegrationSettings'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { settings: integrationSettings } = useIntegrationSettings()
  const visibleItems = NAV_ITEMS.filter((item) =>
    item.to === '/prowlarr' ? isProwlarrAvailable(integrationSettings) : true,
  )

  return (
    <TooltipProvider delayDuration={150}>
      <aside
        style={{ width: collapsed ? 56 : 240 }}
        className="flex flex-shrink-0 flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200 ease-in-out overflow-hidden"
      >
        {/* Brand */}
        <div
          className={cn(
            'flex h-14 shrink-0 items-center border-b border-sidebar-border',
            collapsed ? 'justify-center' : 'px-4',
          )}
        >
          {!collapsed && (
            <span className="flex-1 truncate text-sm font-semibold tracking-wide text-sidebar-foreground">
              Link2NAS
            </span>
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
                <SidebarNavItem item={item} collapsed={collapsed} />
              </li>
            ))}
          </ul>
        </nav>

        {/* User block */}
        <div className="shrink-0 border-t border-sidebar-border">
          {collapsed ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex cursor-default items-center justify-center p-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary select-none">
                    A
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent side="right">admin</TooltipContent>
            </Tooltip>
          ) : (
            <div className="flex items-center gap-3 px-4 py-3">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary select-none">
                A
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-sidebar-foreground">admin</p>
                <p className="truncate text-xs text-muted-foreground">Administrator</p>
              </div>
            </div>
          )}
        </div>
      </aside>
    </TooltipProvider>
  )
}
