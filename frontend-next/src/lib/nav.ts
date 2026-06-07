import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard,
  List,
  Megaphone,
  Search,
  Bell,
  Settings,
  ShieldCheck,
  Wrench,
} from 'lucide-react'
import type { TranslationKey } from '@/i18n'

export interface NavItem {
  to: string
  i18nKey: TranslationKey
  icon: LucideIcon
  /** If true, only marks active on an exact path match (mirrors NavLink `end`). */
  end: boolean
  /** If true, only shown to super_admin users. */
  superAdminOnly?: boolean
  /** If true, hidden when announcements are globally disabled. */
  hideWhenAnnouncementsDisabled?: boolean
  /** If true, hidden when the instance is running in single-user mode. */
  hideInSingleUserMode?: boolean
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard',     i18nKey: 'navDashboard',     icon: LayoutDashboard, end: false },
  { to: '/jobs',          i18nKey: 'navJobs',           icon: List,            end: false },
  { to: '/announcements', i18nKey: 'navAnnouncements',  icon: Megaphone,       end: false, hideWhenAnnouncementsDisabled: true, hideInSingleUserMode: true },
  { to: '/prowlarr',      i18nKey: 'navProwlarr',       icon: Search,          end: false },
  { to: '/notifications', i18nKey: 'navNotifications',  icon: Bell,            end: false },
  { to: '/settings',      i18nKey: 'navSettings',       icon: Settings,        end: false },
  { to: '/admin',         i18nKey: 'navAdmin',          icon: ShieldCheck,     end: false, superAdminOnly: true },
  { to: '/maintenance',   i18nKey: 'navMaintenance',    icon: Wrench,          end: false, superAdminOnly: true },
]

const NON_NAV_KEYS: Record<string, TranslationKey> = {
  '/jobs/new':      'navNewJob',
}

/**
 * Derives a page title from the current pathname.
 * Priority: exact sidebar match → non-nav exact match → longest prefix match.
 */
export function getPageTitle(
  pathname: string,
  t: (key: TranslationKey) => string,
  appName = 'Link2NAS',
): string {
  const exact = NAV_ITEMS.find((item) => pathname === item.to)
  if (exact) return t(exact.i18nKey)

  if (NON_NAV_KEYS[pathname]) return t(NON_NAV_KEYS[pathname])

  const prefix = NAV_ITEMS.filter(
    (item) => !item.end && pathname.startsWith(item.to + '/'),
  ).sort((a, b) => b.to.length - a.to.length)[0]

  return prefix ? t(prefix.i18nKey) : appName
}
