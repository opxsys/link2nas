import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import type { NavItem } from '@/lib/nav'

interface SidebarNavItemProps {
  item: NavItem
  collapsed: boolean
}

function expandedClass({ isActive }: { isActive: boolean }): string {
  return cn(
    'flex h-9 items-center gap-3 rounded-md px-3 text-sm text-muted-foreground transition-colors',
    'hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
    isActive && 'bg-primary/10 text-primary font-medium',
  )
}

function collapsedClass({ isActive }: { isActive: boolean }): string {
  return cn(
    'flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors',
    'hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
    isActive && 'bg-primary/10 text-primary',
  )
}

export default function SidebarNavItem({ item, collapsed }: SidebarNavItemProps) {
  const { to, label, icon: Icon, end } = item

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <NavLink to={to} end={end} className={collapsedClass} aria-label={label}>
            <Icon size={18} aria-hidden="true" />
          </NavLink>
        </TooltipTrigger>
        <TooltipContent side="right" sideOffset={8}>
          {label}
        </TooltipContent>
      </Tooltip>
    )
  }

  return (
    <NavLink to={to} end={end} className={expandedClass}>
      <Icon size={18} aria-hidden="true" className="shrink-0" />
      <span className="truncate">{label}</span>
    </NavLink>
  )
}
