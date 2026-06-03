import { cn } from '@/lib/utils'
import type { NewJobTab } from './newJob.types'

interface NewJobTabsProps {
  activeTab: NewJobTab
  onTabChange: (tab: NewJobTab) => void
}

const TABS: { id: NewJobTab; label: string; hint: string }[] = [
  { id: 'magnet',  label: 'Magnet / Links',  hint: 'Magnet links, direct URLs — one per line' },
  { id: 'torrent', label: 'Torrent Files',   hint: 'One or more .torrent files — one job per file' },
]

export default function NewJobTabs({ activeTab, onTabChange }: NewJobTabsProps) {
  return (
    <nav className="flex border-b border-border" aria-label="New job input method" role="tablist">
      {TABS.map(({ id, label, hint }) => (
        <button
          key={id}
          role="tab"
          aria-selected={activeTab === id}
          title={hint}
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
