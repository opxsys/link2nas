import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { TooltipProvider } from '@/components/ui/tooltip'
import { NAV_ITEMS } from '@/lib/nav'
import SidebarNavItem from './SidebarNavItem'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
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
            {NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <SidebarNavItem item={item} collapsed={collapsed} />
              </li>
            ))}
          </ul>
        </nav>

        {/* Footer */}
        {!collapsed && (
          <div className="shrink-0 border-t border-sidebar-border px-4 py-3">
            <p className="text-xs text-muted-foreground">v3.1-next</p>
          </div>
        )}
      </aside>
    </TooltipProvider>
  )
}
