import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard,
  List,
  PlusCircle,
  Cloud,
  FolderOutput,
  Search,
  Bell,
  Settings,
  ShieldCheck,
  Wrench,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  /** If true, only marks active on an exact path match (mirrors NavLink `end`). */
  end: boolean
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/jobs', label: 'Jobs', icon: List, end: false },
  { to: '/jobs/new', label: 'New Job', icon: PlusCircle, end: true },
  { to: '/providers', label: 'Providers', icon: Cloud, end: false },
  { to: '/destinations', label: 'Destinations', icon: FolderOutput, end: false },
  { to: '/prowlarr', label: 'Prowlarr', icon: Search, end: false },
  { to: '/notifications', label: 'Notifications', icon: Bell, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
  { to: '/admin', label: 'Admin', icon: ShieldCheck, end: false },
  { to: '/maintenance', label: 'Maintenance', icon: Wrench, end: false },
]

/**
 * Derives a page title from the current pathname.
 * Exact matches win over prefix matches; longer prefixes win over shorter ones.
 */
export function getPageTitle(pathname: string): string {
  const exact = NAV_ITEMS.find((item) => pathname === item.to)
  if (exact) return exact.label

  const prefix = NAV_ITEMS.filter(
    (item) => !item.end && pathname.startsWith(item.to + '/'),
  ).sort((a, b) => b.to.length - a.to.length)[0]

  return prefix?.label ?? 'Link2NAS'
}
