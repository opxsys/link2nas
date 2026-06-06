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
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'
import type { SettingsSection } from './settings.types'

interface NavItem {
  id: SettingsSection
  icon: LucideIcon
  labelKey: TranslationKey
}

const NAV_ITEMS: NavItem[] = [
  { id: 'account',       icon: User,        labelKey: 'settingsNavAccount'       },
  { id: 'providers',     icon: Cloud,       labelKey: 'navProviders'             },
  { id: 'destinations',  icon: FolderOutput,labelKey: 'navDestinations'          },
  { id: 'api-keys',      icon: Key,         labelKey: 'settingsNavApiKeys'       },
  { id: 'notifications', icon: Bell,        labelKey: 'settingsNavNotifications' },
  { id: 'prowlarr',      icon: Search,      labelKey: 'navProwlarr'              },
  { id: 'accessibility', icon: Eye,         labelKey: 'settingsNavAccessibility' },
]

interface SettingsNavProps {
  activeSection: SettingsSection
  onSelect: (section: SettingsSection) => void
  showSpace?: boolean
}

export default function SettingsNav({ activeSection, onSelect, showSpace }: SettingsNavProps) {
  const { t } = useI18n()

  const visibleItems = showSpace
    ? [...NAV_ITEMS, { id: 'space' as const, icon: HardDrive, labelKey: 'settingsNavMySpace' as TranslationKey }]
    : NAV_ITEMS

  return (
    <nav
      aria-label={t('ariaSettingsNav')}
      className="rounded-lg border border-border bg-card shadow-sm lg:w-48 lg:shrink-0"
    >
      <ul className="py-1">
        {visibleItems.map(({ id, icon: Icon, labelKey }) => {
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
                {t(labelKey)}
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
