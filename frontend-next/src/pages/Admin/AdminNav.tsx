import {
  LayoutDashboard,
  Users,
  Megaphone,
  Mail,
  ShieldCheck,
  Cpu,
  Trash2,
  AlertTriangle,
  Wrench,
  Settings2,
  Timer,
  KeyRound,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AdminSection } from './admin.types'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

interface NavItem {
  id: AdminSection
  labelKey: TranslationKey
  icon: LucideIcon
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview',      labelKey: 'adminNavOverview',      icon: LayoutDashboard },
  { id: 'general',       labelKey: 'adminNavGeneral',       icon: Settings2 },
  { id: 'users',         labelKey: 'adminNavUsers',         icon: Users },
  { id: 'announcements', labelKey: 'adminNavAnnouncements', icon: Megaphone },
  { id: 'emails',        labelKey: 'adminNavEmails',        icon: Mail },
  { id: 'security',      labelKey: 'adminNavSecurity',      icon: ShieldCheck },
  { id: 'timeouts',      labelKey: 'adminNavTimeouts',      icon: Timer },
  { id: 'runtime',       labelKey: 'adminNavRuntime',       icon: Cpu },
  { id: 'cleanup',       labelKey: 'adminNavCleanup',       icon: Trash2 },
  { id: 'system-events', labelKey: 'adminNavEvents',        icon: AlertTriangle },
  { id: 'maintenance',   labelKey: 'adminNavMaintenance',   icon: Wrench },
  { id: 'sso',           labelKey: 'adminNavSso',           icon: KeyRound },
]

const SINGLE_USER_HIDDEN_SECTIONS = new Set<AdminSection>(['users', 'announcements', 'sso'])

interface Props {
  activeSection: AdminSection
  onSelect: (section: AdminSection) => void
  singleUserMode?: boolean
}

export default function AdminNav({ activeSection, onSelect, singleUserMode }: Props) {
  const { t } = useI18n()
  const visibleItems = singleUserMode
    ? NAV_ITEMS.filter((item) => !SINGLE_USER_HIDDEN_SECTIONS.has(item.id))
    : NAV_ITEMS
  return (
    <nav aria-label={t('ariaAdminSections')} className="rounded-lg border border-border bg-card shadow-sm lg:w-48 lg:shrink-0">
      <ul className="py-1">
        {visibleItems.map(({ id, labelKey, icon: Icon }) => {
          const active = activeSection === id
          return (
            <li key={id}>
              <button
                onClick={() => onSelect(id)}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'flex w-full items-center gap-3 border-l-2 px-4 py-2.5 text-sm transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
                  active
                    ? 'border-primary bg-primary/5 font-medium text-primary'
                    : 'border-transparent text-muted-foreground hover:bg-accent hover:text-foreground',
                )}
              >
                <Icon size={15} aria-hidden="true" className="shrink-0" />
                <span className="truncate">{t(labelKey)}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
