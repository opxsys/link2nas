import {
  User,
  Cloud,
  FolderOutput,
  Key,
  Bell,
  Search,
  Eye,
  HardDrive,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { SettingsSection } from './settings.types'

interface NavItem {
  id: SettingsSection
  label: string
  icon: LucideIcon
}

const NAV_ITEMS: NavItem[] = [
  { id: 'account', label: 'Account', icon: User },
  { id: 'providers', label: 'Providers', icon: Cloud },
  { id: 'destinations', label: 'Destinations', icon: FolderOutput },
  { id: 'api-keys', label: 'API Keys', icon: Key },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'prowlarr', label: 'Prowlarr', icon: Search },
  { id: 'accessibility', label: 'Accessibility', icon: Eye },
]

interface SettingsNavProps {
  activeSection: SettingsSection
  onSelect: (section: SettingsSection) => void
  showSpace?: boolean
}

export default function SettingsNav({ activeSection, onSelect, showSpace }: SettingsNavProps) {
  const visibleItems = showSpace
    ? [...NAV_ITEMS, { id: 'space' as const, label: 'My Space', icon: HardDrive }]
    : NAV_ITEMS

  return (
    <nav
      aria-label="Settings sections"
      className="rounded-lg border border-border bg-card shadow-sm lg:w-48 lg:shrink-0"
    >
      <ul className="py-1">
        {visibleItems.map(({ id, label, icon: Icon }) => {
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
                {label}
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
