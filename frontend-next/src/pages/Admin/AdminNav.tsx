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
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AdminSection } from './admin.types'

interface NavItem {
  id: AdminSection
  label: string
  icon: LucideIcon
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview',      label: 'Overview',       icon: LayoutDashboard },
  { id: 'general',       label: 'General',        icon: Settings2 },
  { id: 'users',         label: 'Users',          icon: Users },
  { id: 'announcements', label: 'Announcements',  icon: Megaphone },
  { id: 'smtp',          label: 'SMTP',           icon: Mail },
  { id: 'security',      label: 'Security',       icon: ShieldCheck },
  { id: 'timeouts',      label: 'Timeouts',       icon: Timer },
  { id: 'runtime',       label: 'Runtime',        icon: Cpu },
  { id: 'cleanup',       label: 'Cleanup',        icon: Trash2 },
  { id: 'system-events', label: 'System Events',  icon: AlertTriangle },
  { id: 'maintenance',   label: 'Maintenance',    icon: Wrench },
]

interface Props {
  activeSection: AdminSection
  onSelect: (section: AdminSection) => void
}

export default function AdminNav({ activeSection, onSelect }: Props) {
  return (
    <nav aria-label="Admin sections" className="rounded-lg border border-border bg-card shadow-sm lg:w-48 lg:shrink-0">
      <ul className="py-1">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
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
