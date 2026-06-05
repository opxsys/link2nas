import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import type { NavItem } from '@/lib/nav'
import { useI18n } from '@/i18n'

interface SidebarNavItemProps {
  item: NavItem
  collapsed: boolean
  badge?: number
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

function BadgePill({ count }: { count: number }) {
  if (count <= 0) return null
  const label = count > 99 ? '99+' : String(count)
  return (
    <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-semibold leading-none text-primary-foreground">
      {label}
    </span>
  )
}

export default function SidebarNavItem({ item, collapsed, badge }: SidebarNavItemProps) {
  const { to, i18nKey, icon: Icon, end } = item
  const { t } = useI18n()
  const label = t(i18nKey)
  const hasBadge = badge !== undefined && badge > 0

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <NavLink to={to} end={end} className={collapsedClass} aria-label={label}>
            <span className="relative">
              <Icon size={18} aria-hidden="true" />
              {hasBadge && (
                <span className="absolute -right-1.5 -top-1.5 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-primary px-0.5 text-[9px] font-bold leading-none text-primary-foreground">
                  {badge! > 99 ? '99+' : badge}
                </span>
              )}
            </span>
          </NavLink>
        </TooltipTrigger>
        <TooltipContent side="right" sideOffset={8}>
          {label}{hasBadge ? ` (${badge})` : ''}
        </TooltipContent>
      </Tooltip>
    )
  }

  return (
    <NavLink to={to} end={end} className={expandedClass}>
      <Icon size={18} aria-hidden="true" className="shrink-0" />
      <span className="truncate">{label}</span>
      <BadgePill count={badge ?? 0} />
    </NavLink>
  )
}
