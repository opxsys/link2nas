import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard,
  List,
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
  { to: '/prowlarr', label: 'Prowlarr', icon: Search, end: false },
  { to: '/notifications', label: 'My Notifications', icon: Bell, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
  { to: '/admin', label: 'Admin', icon: ShieldCheck, end: false },
  { to: '/maintenance', label: 'Maintenance', icon: Wrench, end: false },
]

/**
 * Titles for pages that exist but are not top-level sidebar items.
 * /jobs/new is an action; /providers and /destinations will live under Settings.
 */
const NON_NAV_TITLES: Record<string, string> = {
  '/jobs/new': 'New Job',
  '/providers': 'Providers',
  '/destinations': 'Destinations',
}

/**
 * Derives a page title from the current pathname.
 * Priority: exact sidebar match → non-nav exact match → longest prefix match.
 */
export function getPageTitle(pathname: string): string {
  const exact = NAV_ITEMS.find((item) => pathname === item.to)
  if (exact) return exact.label

  if (NON_NAV_TITLES[pathname]) return NON_NAV_TITLES[pathname]

  const prefix = NAV_ITEMS.filter(
    (item) => !item.end && pathname.startsWith(item.to + '/'),
  ).sort((a, b) => b.to.length - a.to.length)[0]

  return prefix?.label ?? 'Link2NAS'
}
