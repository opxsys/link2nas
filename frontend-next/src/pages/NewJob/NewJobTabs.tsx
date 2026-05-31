import { cn } from '@/lib/utils'
import type { NewJobTab } from './newJob.types'

interface NewJobTabsProps {
  activeTab: NewJobTab
  onTabChange: (tab: NewJobTab) => void
}

const TABS: { id: NewJobTab; label: string }[] = [
  { id: 'magnet', label: 'Magnet / Links' },
  { id: 'torrent', label: 'Torrent Upload' },
  { id: 'batch', label: 'Batch Upload' },
]

export default function NewJobTabs({ activeTab, onTabChange }: NewJobTabsProps) {
  return (
    <nav className="flex border-b border-border" aria-label="New job input method" role="tablist">
      {TABS.map(({ id, label }) => (
        <button
          key={id}
          role="tab"
          aria-selected={activeTab === id}
          onClick={() => onTabChange(id)}
          className={cn(
            'px-5 py-3 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset',
            activeTab === id
              ? 'border-b-2 border-primary font-medium text-primary'
              : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {label}
        </button>
      ))}
    </nav>
  )
}
